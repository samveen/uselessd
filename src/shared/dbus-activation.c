/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd/uselessd.

  Copyright 2010 Lennart Poettering
  Copyright 2014 The Initfinder General

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <errno.h>
#include <unistd.h>
#include <dbus/dbus.h>

#include "log.h"
#include "strv.h"
#include "mkdir.h"
#include "missing.h"
#include "special.h"
#include "manager.h"

#include "dbus-activation.h"

#define CONNECTIONS_MAX 512

/* Well-known address (http://dbus.freedesktop.org/doc/dbus-specification.html#message-bus-types) */
#define DBUS_SYSTEM_BUS_DEFAULT_ADDRESS "unix:path=/var/run/dbus/system_bus_socket"
/* Only used as a fallback */
#define DBUS_SESSION_BUS_DEFAULT_ADDRESS "autolaunch:"

static void shutdown_connection(Manager *m, DBusConnection *c) {
        set_remove(m->bus_connections, c);
        set_remove(m->bus_connections_for_dispatch, c);
        set_free_free(BUS_CONNECTION_SUBSCRIBED(m, c));

        if (m->queued_message_connection == c) {
                m->queued_message_connection = NULL;

                if (m->queued_message) {
                        dbus_message_unref(m->queued_message);
                        m->queued_message = NULL;
                }
        }

        dbus_connection_set_dispatch_status_function(c, NULL, NULL, NULL);
        /* system manager cannot afford to block on DBus */
        if (m->running_as != SYSTEMD_SYSTEM)
                dbus_connection_flush(c);
        dbus_connection_close(c);
        dbus_connection_unref(c);
}

static void bus_done_api(Manager *m) {
        if (!m->api_bus)
                return;

        if (m->running_as == SYSTEMD_USER)
                shutdown_connection(m, m->api_bus);

        m->api_bus = NULL;

        if (m->queued_message) {
                dbus_message_unref(m->queued_message);
                m->queued_message = NULL;
        }
}

static void bus_done_system(Manager *m) {
        if (!m->system_bus)
                return;

        if (m->running_as == SYSTEMD_SYSTEM)
                bus_done_api(m);

        shutdown_connection(m, m->system_bus);
        m->system_bus = NULL;
}

static void bus_done_private(Manager *m) {
        if (!m->private_bus)
                return;

        dbus_server_disconnect(m->private_bus);
        dbus_server_unref(m->private_bus);
        m->private_bus = NULL;
}

void bus_done(Manager *m) {
        DBusConnection *c;

        bus_done_api(m);
        bus_done_system(m);
        bus_done_private(m);

        while ((c = set_steal_first(m->bus_connections)))
                shutdown_connection(m, c);

        while ((c = set_steal_first(m->bus_connections_for_dispatch)))
                shutdown_connection(m, c);

        set_free(m->bus_connections);
        set_free(m->bus_connections_for_dispatch);

        if (m->name_data_slot >= 0)
                dbus_pending_call_free_data_slot(&m->name_data_slot);

        if (m->conn_data_slot >= 0)
                dbus_pending_call_free_data_slot(&m->conn_data_slot);

        if (m->subscribed_data_slot >= 0)
                dbus_connection_free_data_slot(&m->subscribed_data_slot);
}

unsigned bus_dispatch(Manager *m) {
        DBusConnection *c;

        assert(m);

        if (m->queued_message) {
                /* If we cannot get rid of this message we won't
                 * dispatch any D-Bus messages, so that we won't end
                 * up wanting to queue another message. */

                if (m->queued_message_connection)
                        if (!dbus_connection_send(m->queued_message_connection, m->queued_message, NULL))
                                return 0;

                dbus_message_unref(m->queued_message);
                m->queued_message = NULL;
                m->queued_message_connection = NULL;
        }

        if ((c = set_first(m->bus_connections_for_dispatch))) {
                if (dbus_connection_dispatch(c) == DBUS_DISPATCH_COMPLETE)
                        set_move_one(m->bus_connections, m->bus_connections_for_dispatch, c);

                return 1;
        }

        return 0;
}

static void bus_dispatch_status(DBusConnection *bus, DBusDispatchStatus status, void *data)  {
        Manager *m = data;

        assert(bus);
        assert(m);

        /* We maintain two sets, one for those connections where we
         * requested a dispatch, and another where we didn't. And then,
         * we move the connections between the two sets. */

        if (status == DBUS_DISPATCH_COMPLETE)
                set_move_one(m->bus_connections, m->bus_connections_for_dispatch, bus);
        else
                set_move_one(m->bus_connections_for_dispatch, m->bus_connections, bus);
}

static uint32_t bus_flags_to_events(DBusWatch *bus_watch) {
        unsigned flags;
        uint32_t events = 0;

        assert(bus_watch);

        /* no watch flags for disabled watches */
        if (!dbus_watch_get_enabled(bus_watch))
                return 0;

        flags = dbus_watch_get_flags(bus_watch);

        if (flags & DBUS_WATCH_READABLE)
                events |= EPOLLIN;
        if (flags & DBUS_WATCH_WRITABLE)
                events |= EPOLLOUT;

        return events | EPOLLHUP | EPOLLERR;
}

static unsigned bus_events_to_flags(uint32_t events) {
        unsigned flags = 0;

        if (events & EPOLLIN)
                flags |= DBUS_WATCH_READABLE;
        if (events & EPOLLOUT)
                flags |= DBUS_WATCH_WRITABLE;
        if (events & EPOLLHUP)
                flags |= DBUS_WATCH_HANGUP;
        if (events & EPOLLERR)
                flags |= DBUS_WATCH_ERROR;

        return flags;
}

void bus_watch_event(Manager *m, Watch *w, int events) {
        assert(m);
        assert(w);

        /* This is called by the event loop whenever there is
         * something happening on D-Bus' file handles. */

        if (!dbus_watch_get_enabled(w->data.bus_watch))
                return;

        dbus_watch_handle(w->data.bus_watch, bus_events_to_flags(events));
}

static dbus_bool_t bus_add_watch(DBusWatch *bus_watch, void *data) {
        Manager *m = data;
        Watch *w;
        struct epoll_event ev;

        assert(bus_watch);
        assert(m);

        if (!(w = new0(Watch, 1)))
                return FALSE;

        w->fd = dbus_watch_get_unix_fd(bus_watch);
        w->type = WATCH_DBUS_WATCH;
        w->data.bus_watch = bus_watch;

        zero(ev);
        ev.events = bus_flags_to_events(bus_watch);
        ev.data.ptr = w;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, w->fd, &ev) < 0) {

                if (errno != EEXIST) {
                        free(w);
                        return FALSE;
                }

                /* Hmm, bloody D-Bus creates multiple watches on the
                 * same fd. epoll() does not like that. As a dirty
                 * hack we simply dup() the fd and hence get a second
                 * one we can safely add to the epoll(). */

                if ((w->fd = dup(w->fd)) < 0) {
                        free(w);
                        return FALSE;
                }

                if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, w->fd, &ev) < 0) {
                        close_nointr_nofail(w->fd);
                        free(w);
                        return FALSE;
                }

                w->fd_is_dupped = true;
        }

        dbus_watch_set_data(bus_watch, w, NULL);

        return TRUE;
}

static void bus_remove_watch(DBusWatch *bus_watch, void *data) {
        Manager *m = data;
        Watch *w;

        assert(bus_watch);
        assert(m);

        w = dbus_watch_get_data(bus_watch);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_WATCH);
        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);

        if (w->fd_is_dupped)
                close_nointr_nofail(w->fd);

        free(w);
}

static void bus_toggle_watch(DBusWatch *bus_watch, void *data) {
        Manager *m = data;
        Watch *w;
        struct epoll_event ev;

        assert(bus_watch);
        assert(m);

        w = dbus_watch_get_data(bus_watch);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_WATCH);

        zero(ev);
        ev.events = bus_flags_to_events(bus_watch);
        ev.data.ptr = w;

        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_MOD, w->fd, &ev) == 0);
}


static int bus_timeout_arm(Manager *m, Watch *w) {
        struct itimerspec its = {};

        assert(m);
        assert(w);

        if (dbus_timeout_get_enabled(w->data.bus_timeout)) {
                timespec_store(&its.it_value, dbus_timeout_get_interval(w->data.bus_timeout) * USEC_PER_MSEC);
                its.it_interval = its.it_value;
        }

        if (timerfd_settime(w->fd, 0, &its, NULL) < 0)
                return -errno;

        return 0;
}

void bus_timeout_event(Manager *m, Watch *w, int events) {
        assert(m);
        assert(w);

        /* This is called by the event loop whenever there is
         * something happening on D-Bus' file handles. */

        if (!(dbus_timeout_get_enabled(w->data.bus_timeout)))
                return;

        dbus_timeout_handle(w->data.bus_timeout);
}

static dbus_bool_t bus_add_timeout(DBusTimeout *timeout, void *data) {
        Manager *m = data;
        Watch *w;
        struct epoll_event ev;

        assert(timeout);
        assert(m);

        if (!(w = new0(Watch, 1)))
                return FALSE;

        if ((w->fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC)) < 0)
                goto fail;

        w->type = WATCH_DBUS_TIMEOUT;
        w->data.bus_timeout = timeout;

        if (bus_timeout_arm(m, w) < 0)
                goto fail;

        zero(ev);
        ev.events = EPOLLIN;
        ev.data.ptr = w;

        if (epoll_ctl(m->epoll_fd, EPOLL_CTL_ADD, w->fd, &ev) < 0)
                goto fail;

        dbus_timeout_set_data(timeout, w, NULL);

        return TRUE;

fail:
        if (w->fd >= 0)
                close_nointr_nofail(w->fd);

        free(w);
        return FALSE;
}

static void bus_remove_timeout(DBusTimeout *timeout, void *data) {
        Manager *m = data;
        Watch *w;

        assert(timeout);
        assert(m);

        w = dbus_timeout_get_data(timeout);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_TIMEOUT);

        assert_se(epoll_ctl(m->epoll_fd, EPOLL_CTL_DEL, w->fd, NULL) >= 0);
        close_nointr_nofail(w->fd);
        free(w);
}

static void bus_toggle_timeout(DBusTimeout *timeout, void *data) {
        Manager *m = data;
        Watch *w;
        int r;

        assert(timeout);
        assert(m);

        w = dbus_timeout_get_data(timeout);
        if (!w)
                return;

        assert(w->type == WATCH_DBUS_TIMEOUT);

        if ((r = bus_timeout_arm(m, w)) < 0)
                log_error("Failed to rearm timer: %s", strerror(-r));
}

static int bus_setup_loop(Manager *m, DBusConnection *bus) {
        assert(m);
        assert(bus);

        dbus_connection_set_exit_on_disconnect(bus, FALSE);

        if (!dbus_connection_set_watch_functions(bus, bus_add_watch, bus_remove_watch, bus_toggle_watch, m, NULL) ||
            !dbus_connection_set_timeout_functions(bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL))
                return log_oom();

        if (set_put(m->bus_connections_for_dispatch, bus) < 0)
                return log_oom();

        dbus_connection_set_dispatch_status_function(bus, bus_dispatch_status, m, NULL);
        return 0;
}

static int manager_bus_async_register(Manager *m, DBusConnection **conn) {
        DBusMessage *message = NULL;
        DBusPendingCall *pending = NULL;

        message = dbus_message_new_method_call(DBUS_SERVICE_DBUS,
                                               DBUS_PATH_DBUS,
                                               DBUS_INTERFACE_DBUS,
                                               "Hello");
        if (!message)
                goto oom;

        if (!dbus_connection_send_with_reply(*conn, message, &pending, -1))
                goto oom;

        if (!dbus_pending_call_set_data(pending, m->conn_data_slot, conn, NULL))
                goto oom;

        dbus_message_unref(message);
        dbus_pending_call_unref(pending);

        return 0;
oom:
        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }

        if (message)
                dbus_message_unref(message);

        return -ENOMEM;
}

static DBusConnection* manager_bus_connect_private(Manager *m, DBusBusType type) {
        const char *address;
        DBusConnection *connection;
        DBusError error;

        switch (type) {
        case DBUS_BUS_SYSTEM:
                address = getenv("DBUS_SYSTEM_BUS_ADDRESS");
                if (!address || !address[0])
                        address = DBUS_SYSTEM_BUS_DEFAULT_ADDRESS;
                break;
        case DBUS_BUS_SESSION:
                address = getenv("DBUS_SESSION_BUS_ADDRESS");
                if (!address || !address[0])
                        address = DBUS_SESSION_BUS_DEFAULT_ADDRESS;
                break;
        default:
                assert_not_reached("Invalid bus type");
        }

        dbus_error_init(&error);

        connection = dbus_connection_open_private(address, &error);
        if (!connection) {
                log_warning("Failed to open private bus connection: %s", error.message);
                goto fail;
        }

        return connection;

fail:
        dbus_error_free(&error);
        return NULL;
}

static int bus_init_system(Manager *m) {
        int r;

        if (m->system_bus)
                return 0;

        m->system_bus = manager_bus_connect_private(m, DBUS_BUS_SYSTEM);
        if (!m->system_bus) {
                log_debug("Failed to connect to system D-Bus, retrying later");
                r = 0;
                goto fail;
        }

        r = bus_setup_loop(m, m->system_bus);
        if (r < 0)
                goto fail;

        r = manager_bus_async_register(m, &m->system_bus);
        if (r < 0)
                goto fail;

        return 0;
fail:
        bus_done_system(m);

        return r;
}

static int bus_init_api(Manager *m) {
        int r;

        if (m->api_bus)
                return 0;

        if (m->running_as == SYSTEMD_SYSTEM) {
                m->api_bus = m->system_bus;
                /* In this mode there is no distinct connection to the API bus,
                 * the API is published on the system bus.
                 * bus_register_cb() is aware of that and will init the API
                 * when the system bus gets registered.
                 * No need to setup anything here. */
                return 0;
        }

        m->api_bus = manager_bus_connect_private(m, DBUS_BUS_SESSION);
        if (!m->api_bus) {
                log_debug("Failed to connect to API D-Bus, retrying later");
                r = 0;
                goto fail;
        }

        r = bus_setup_loop(m, m->api_bus);
        if (r < 0)
                goto fail;

        r = manager_bus_async_register(m, &m->api_bus);
        if (r < 0)
                goto fail;

        return 0;
fail:
        bus_done_api(m);

        return r;
}

static dbus_bool_t allow_only_same_user(DBusConnection *connection, unsigned long uid, void *data) {
        return uid == 0 || uid == geteuid();
}

static void bus_new_connection(
                DBusServer *server,
                DBusConnection *new_connection,
                void *data) {

        Manager *m = data;

        assert(m);

        if (set_size(m->bus_connections) >= CONNECTIONS_MAX) {
                log_error("Too many concurrent connections.");
                return;
        }

        dbus_connection_set_unix_user_function(new_connection, allow_only_same_user, NULL, NULL);

        if (bus_setup_loop(m, new_connection) < 0)
                return;

        /* No object path callbacks registered; analyze more thoroughly later. */

        log_debug("Accepted connection on private bus.");

        dbus_connection_ref(new_connection);
}

static int bus_init_private(Manager *m) {
        DBusError error;
        int r;
        static const char *const external_only[] = {
                "EXTERNAL",
                NULL
        };

        assert(m);

        dbus_error_init(&error);

        if (m->private_bus)
                return 0;

        if (m->running_as == SYSTEMD_SYSTEM) {
                unlink("/run/systemd/private");
                m->private_bus = dbus_server_listen("unix:path=/run/systemd/private", &error);
        } else {
                const char *e;
                char *p;
                char *escaped;

                e = getenv("XDG_RUNTIME_DIR");
                if (!e)
                        return 0;

                if (asprintf(&p, "%s/systemd/private", e) < 0) {
                        r = log_oom();
                        goto fail;
                }

                mkdir_parents_label(p, 0755);
                unlink(p);
                free(p);

                escaped = dbus_address_escape_value(e);
                if (!escaped) {
                        r = log_oom();
                        goto fail;
                }
                if (asprintf(&p, "unix:path=%s/systemd/private", escaped) < 0) {
                        dbus_free(escaped);
                        r = log_oom();
                        goto fail;
                }
                dbus_free(escaped);

                m->private_bus = dbus_server_listen(p, &error);
                free(p);
        }

        if (!m->private_bus) {
                log_error("Failed to create private D-Bus server: %s", error.message);
                r = -EIO;
                goto fail;
        }

        if (!dbus_server_set_auth_mechanisms(m->private_bus, (const char**) external_only) ||
            !dbus_server_set_watch_functions(m->private_bus, bus_add_watch, bus_remove_watch, bus_toggle_watch, m, NULL) ||
            !dbus_server_set_timeout_functions(m->private_bus, bus_add_timeout, bus_remove_timeout, bus_toggle_timeout, m, NULL)) {
                r = log_oom();
                goto fail;
        }

        dbus_server_set_new_connection_function(m->private_bus, bus_new_connection, m, NULL);

        log_debug("Successfully created private D-Bus server.");

        return 0;

fail:
        bus_done_private(m);
        dbus_error_free(&error);

        return r;
}

int bus_init(Manager *m, bool try_bus_connect) {
        int r;

        if (set_ensure_allocated(&m->bus_connections, trivial_hash_func, trivial_compare_func) < 0 ||
            set_ensure_allocated(&m->bus_connections_for_dispatch, trivial_hash_func, trivial_compare_func) < 0)
                return log_oom();

        if (m->name_data_slot < 0)
                if (!dbus_pending_call_allocate_data_slot(&m->name_data_slot))
                        return log_oom();

        if (m->conn_data_slot < 0)
                if (!dbus_pending_call_allocate_data_slot(&m->conn_data_slot))
                        return log_oom();

        if (m->subscribed_data_slot < 0)
                if (!dbus_connection_allocate_data_slot(&m->subscribed_data_slot))
                        return log_oom();

        if (try_bus_connect) {
                if ((r = bus_init_system(m)) < 0 ||
                    (r = bus_init_api(m)) < 0)
                        return r;
        }

        r = bus_init_private(m);
        if (r < 0)
                return r;

        return 0;
}

static void query_pid_pending_cb(DBusPendingCall *pending, void *userdata) {
        Manager *m = userdata;
        DBusMessage *reply;
        DBusError error;
        const char *name;

        dbus_error_init(&error);

        assert_se(name = BUS_PENDING_CALL_NAME(m, pending));
        assert_se(reply = dbus_pending_call_steal_reply(pending));

        switch (dbus_message_get_type(reply)) {

        case DBUS_MESSAGE_TYPE_ERROR:

                assert_se(dbus_set_error_from_message(&error, reply));
                log_warning("GetConnectionUnixProcessID() failed: %s", error.message);
                break;

        case DBUS_MESSAGE_TYPE_METHOD_RETURN: {
                uint32_t r;

                if (!dbus_message_get_args(reply,
                                           &error,
                                           DBUS_TYPE_UINT32, &r,
                                           DBUS_TYPE_INVALID)) {
                        log_error("Failed to parse GetConnectionUnixProcessID() reply: %s", error.message);
                        break;
                }

                manager_dispatch_bus_query_pid_done(m, name, (pid_t) r);
                break;
        }

        default:
                assert_not_reached("Invalid reply message");
        }

        dbus_message_unref(reply);
        dbus_error_free(&error);
}

int bus_query_pid(Manager *m, const char *name) {
        DBusMessage *message = NULL;
        DBusPendingCall *pending = NULL;
        char *n = NULL;

        assert(m);
        assert(name);

        if (!(message = dbus_message_new_method_call(
                              DBUS_SERVICE_DBUS,
                              DBUS_PATH_DBUS,
                              DBUS_INTERFACE_DBUS,
                              "GetConnectionUnixProcessID")))
                goto oom;

        if (!(dbus_message_append_args(
                              message,
                              DBUS_TYPE_STRING, &name,
                              DBUS_TYPE_INVALID)))
                goto oom;

        if (!dbus_connection_send_with_reply(m->api_bus, message, &pending, -1))
                goto oom;

        if (!(n = strdup(name)))
                goto oom;

        if (!dbus_pending_call_set_data(pending, m->name_data_slot, n, free))
                goto oom;

        n = NULL;

        if (!dbus_pending_call_set_notify(pending, query_pid_pending_cb, m, NULL))
                goto oom;

        dbus_message_unref(message);
        dbus_pending_call_unref(pending);

        return 0;

oom:
        free(n);

        if (pending) {
                dbus_pending_call_cancel(pending);
                dbus_pending_call_unref(pending);
        }

        if (message)
                dbus_message_unref(message);

        return -ENOMEM;
}
