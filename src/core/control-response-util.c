/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of uselessd.

  Copyright 2014 The Initfinder General

  uselessd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  uselessd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with uselessd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <systemd/sd-shutdown.h>

#include "hashmap.h"
#include "install.h"
#include "log.h"
#include "job.h"
#include "unit.h"
#include "kill.h"
#include "path-lookup.h"
#include "path-util.h"
#include "util.h"
#include "cgroup-util.h"
#include "strv.h"
#include "cgroup.h"
#include "fileio.h"
#include "virt.h"
#include "killall.h"
#include "watchdog.h"
#include "switch-root.h"
#include "special.h"

#include "control-response-util.h"

UnitFileScope get_arg_scope(void) {
        int scope;
        _cleanup_free_ char *p = NULL;

        scope = read_one_line_file(SPECIAL_ARG_SCOPE, &p);
        if (scope < 0)
                return -1;

        if (streq("system", p))
                return UNIT_FILE_SYSTEM;
        else if (streq("global", p))
                return UNIT_FILE_GLOBAL;
        else if (streq("user", p))
                return UNIT_FILE_USER;
        else
                return UNIT_FILE_SYSTEM; /* default */
}

const char* get_arg_root(void) {
        int root;
        const char *p = NULL;

        root = read_one_line_file(SPECIAL_ARG_ROOT, (char **)&p);
        if (root < 0)
                return "unknown";

        return p;
}

JobMode get_arg_job_mode(void) {
        int mode;
        _cleanup_free_ char *p = NULL;

        mode = read_one_line_file(SPECIAL_ARG_JOB_MODE, &p);
        if (mode < 0)
                return -1;

        if (streq("fail", p))
                return JOB_FAIL;
        else if (streq("replace", p))
                return JOB_REPLACE;
        else if (streq("replace-irreversibly", p))
                return JOB_REPLACE_IRREVERSIBLY;
        else if (streq("isolate", p))
                return JOB_ISOLATE;
        else if (streq("ignore-dependencies", p))
                return JOB_IGNORE_DEPENDENCIES;
        else if (streq("ignore-requirements", p))
                return JOB_IGNORE_REQUIREMENTS;
        else
                return JOB_REPLACE; /* default */
}

JobType get_arg_job_type(void) {
        int type;
        _cleanup_free_ char *p = NULL;

        type = read_one_line_file(SPECIAL_ARG_JOB_TYPE, &p);
        if (type < 0)
                return -1;

        if (streq("start", p))
                return JOB_START;
        else if (streq("stop", p))
                return JOB_STOP;
        else if (streq("restart", p))
                return JOB_RESTART;
        else if (streq("reload", p))
                return JOB_RELOAD;
        else if (streq("reload-or-start", p))
                return JOB_RELOAD_OR_START;
        else if (streq("try-restart", p))
                return JOB_TRY_RESTART;
        else if (streq("verify-active", p))
                return JOB_VERIFY_ACTIVE;
        else return JOB_NOP;
}

KillWho get_kill_who(void) {
        int kw;
        _cleanup_free_ char *p = NULL;

        kw = read_one_line_file("/run/systemd/manager/kill-who", &p);
        if (kw < 0)
                return -1;

        if (streq("all", p))
                return KILL_ALL;
        else if (streq("control", p))
                return KILL_CONTROL;
        else if (streq("main", p))
                return KILL_MAIN;
        else return KILL_ALL;
}

int32_t get_kill_signal(void) {
        int getsig, sig;
        _cleanup_free_ char *p = NULL;

        getsig = read_one_line_file("/run/systemd/manager/kill-signal", &p);
        if (getsig < 0)
                return 15; /* SIGTERM */

        sig = signal_from_string_try_harder(p);
        if (sig <= 0)
                return 15;

        return sig;
}

bool test_runtime(void) {
        int r;
        _cleanup_free_ char *p = NULL;

        r = read_one_line_file(SPECIAL_ARG_RUNTIME, &p);
        if (r < 0)
                return false;

        return parse_boolean(p) > 0;
}

bool test_force(void) {
        int r;
        _cleanup_free_ char *p = NULL;

        r = read_one_line_file(SPECIAL_ARG_FORCE, &p);
        if (r < 0)
                return false;

        return parse_boolean(p) > 0;
}

/* TODO: carries_install_info.
* Fix encoding in UnitFileChange logging,
* or remove entirely.
* enable_sysv_units()...
*/
void unit_file_operation_tango(const char *param, int fifoout) {
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        UnitFileState state;
        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        const char *msg;
        char *p;
        char *s[] = {};
        int r;
        int k;

        if (running_in_chroot() > 0) {
                log_info("Running in chroot, ignoring request.");
                return;
        }

        argruntime = test_runtime();
        argforce = test_force();

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        if (streq("get-default-target", param)) {
                char *default_target;

                r = unit_file_get_default(argscope, argroot, &default_target);
                if (default_target)
                        loop_write(fifoout, default_target, strlen(default_target), false);
                        loop_write(fifoout, "\n", strlen("\n"), false);

        } else if (streq("set-default-target", param)) {
                k = read_one_line_file("/run/systemd/manager/set-default-target", &p);
                if (k < 0)
                        log_error("Failed to get default target to set: %s.", strerror(-k));

                r = unit_file_set_default(argscope, argroot, (char *)p, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to set default target: %s.", strerror(-r));

        } else if (streq("enable", param)) {
                k = read_one_line_file("/run/systemd/manager/enable", s);
                if (k < 0)
                        log_error("Failed to get unit file to enable: %s.", strerror(-k));

                r = unit_file_enable(argscope, argruntime, argroot, s, argforce, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to enable unit file: %s.", strerror(-r));

        } else if (streq("reenable", param)) {
                k = read_one_line_file("/run/systemd/manager/reenable", s);
                if (k < 0)
                        log_error("Failed to get unit file to reenable: %s.", strerror(-k));

                r = unit_file_reenable(argscope, argruntime, argroot, s, argforce, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to reenable unit file: %s.", strerror(-r));

        } else if (streq("disable", param)) {
                k = read_one_line_file("/run/systemd/manager/disable", s);
                if (k < 0)
                        log_error("Failed to get unit file to disable: %s.", strerror(-k));

                r = unit_file_disable(argscope, argruntime, argroot, s, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to disable unit file: %s.", strerror(-r));

        } else if (streq("preset", param)) {
                k = read_one_line_file("/run/systemd/manager/preset", s);
                if (k < 0)
                        log_error("Failed to get unit file preset policy: %s.", strerror(-k));

                r = unit_file_preset(argscope, argruntime, argroot, s, argforce, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to enable unit file preset policy: %s.", strerror(-r));

        } else if (streq("mask", param)) {
                k = read_one_line_file("/run/systemd/manager/mask", s);
                if (k < 0)
                        log_error("Failed to get unit file to mask: %s.", strerror(-k));

                r = unit_file_mask(argscope, argruntime, argroot, s, argforce, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to mask unit file: %s.", strerror(-r));

        } else if (streq("unmask", param)) {
                k = read_one_line_file("/run/systemd/manager/unmask", s);
                if (k < 0)
                        log_error("Failed to get unit file to unmask: %s.", strerror(-k));

                r = unit_file_unmask(argscope, argruntime, argroot, s, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to unmask unit file: %s.", strerror(-r));

        } else if (streq("link", param)) {
                k = read_one_line_file("/run/systemd/manager/link", s);
                if (k < 0)
                        log_error("Failed to get unit file to link: %s.", strerror(-k));

                r = unit_file_link(argscope, argruntime, argroot, s, argforce, &changes, &n_changes);
                if (r < 0)
                        log_error("Failed to link unit file: %s.", strerror(-r));

        } else if (streq("is-enabled", param)) {
                k = read_one_line_file("/run/systemd/manager/is-enabled", (char **)&p);
                if (k < 0)
                        log_error("Failed to get unit file to check state on: %s.", strerror(-k));

                state = unit_file_get_state(argscope, argroot, p);
                if (state < 0)
                        log_error("Failed to get state for unit file.");
                        return;

                msg = unit_file_state_to_string(state);
                loop_write(fifoout, msg, strlen(msg), false);
                loop_write(fifoout, "\n", strlen("\n"), false);

        } else {
                log_error("Unknown parameter.");
        }

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void output_unit_file_list(const UnitFileList *units, unsigned c) {
        unsigned max_id_len, id_cols, state_cols, n_shown = 0;
        const UnitFileList *u;
        FILE *f;

        max_id_len = sizeof("UNIT FILE")-1;
        state_cols = sizeof("STATE")-1;
        for (u = units; u < units + c; u++) {

                max_id_len = MAX(max_id_len, strlen(path_get_file_name(u->path)));
                state_cols = MAX(state_cols, strlen(unit_file_state_to_string(u->state)));
        }

        id_cols = max_id_len;

        f = fopen("/run/systemd/uflist", "w");
        if (ferror(f)) {
                fclose(f);
                log_warning("Failed to write unit file list to file.");
        }

        for (u = units; u < units + c; u++) {
                _cleanup_free_ char *e = NULL;
                const char *on, *off;
                const char *id;

                n_shown++;

                if (u->state == UNIT_FILE_MASKED ||
                    u->state == UNIT_FILE_MASKED_RUNTIME ||
                    u->state == UNIT_FILE_DISABLED ||
                    u->state == UNIT_FILE_INVALID) {
                        on  = ansi_highlight_red();
                        off = ansi_highlight_off();
                } else if (u->state == UNIT_FILE_ENABLED) {
                        on  = ansi_highlight_green();
                        off = ansi_highlight_off();
                } else
                        on = off = "";

                id = path_get_file_name(u->path);

                e = ellipsize(id, id_cols, 33);

                fprintf(f, "%-*s %s%-*s%s\n",
                       id_cols, e ? e : id,
                       on, state_cols, unit_file_state_to_string(u->state), off);
        }

        fprintf(f, "\n%u unit files listed.\n", n_shown);

        fflush(f);
        fclose(f);
}

void list_unit_files(void) {
        Hashmap *h;
        UnitFileList *u;
        _cleanup_free_ UnitFileList *units = NULL;
        unsigned count = 0, n_units = 0;
        Iterator i;
        int r;
        UnitFileScope argscope;

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        h = hashmap_new(string_hash_func, string_compare_func);
        if (!h)
                log_oom();

        r = unit_file_get_list(argscope, NULL, h);
        if (r < 0) {
                unit_file_list_free(h);
                log_error("Failed to get unit file list: %s", strerror(-r));
                return;
        }

        n_units = hashmap_size(h);

        if (n_units == 0)
                return;

        units = new(UnitFileList, n_units);
        if (!units) {
                unit_file_list_free(h);
                log_oom();
        }

        HASHMAP_FOREACH(u, h, i) {
                memcpy(units + count++, u, sizeof(UnitFileList));
                free(u);
        }

        hashmap_free(h);

        output_unit_file_list(units, count);
}

void unit_systemctl_status_print(Unit *u) {
        printf("%s - %s", u->id, u->description);
        printf("Loaded: %s", unit_load_state_to_string(u->load_state));
        printf("Active: %s", unit_active_state_to_string(unit_active_state(u)));

        if (u->cgroup_path)
                printf("CGroup: %s", u->cgroup_path);

}

int send_shutdownd(usec_t t, char mode, bool dry_run, bool warn, const char *message) {
        _cleanup_close_ int fd;
        struct sd_shutdown_command c = {
                .usec = t,
                .mode = mode,
                .dry_run = dry_run,
                .warn_wall = warn,
        };
        union sockaddr_union sockaddr = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/shutdownd",
        };
        struct iovec iovec[2] = {
                {.iov_base = (char*) &c,
                 .iov_len = offsetof(struct sd_shutdown_command, wall_message),
                }
        };
        struct msghdr msghdr = {
                .msg_name = &sockaddr,
                .msg_namelen = offsetof(struct sockaddr_un, sun_path)
                               + sizeof("/run/systemd/shutdownd") - 1,
                .msg_iov = iovec,
                .msg_iovlen = 1,
        };

        fd = socket(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (!isempty(message)) {
                iovec[1].iov_base = (char*) message;
                iovec[1].iov_len = strlen(message);
                msghdr.msg_iovlen++;
        }

        if (sendmsg(fd, &msghdr, MSG_NOSIGNAL) < 0)
                return -errno;

        return 0;
}

int cgroup_set_property(
                Unit *u,
                CGroupContext *c,
                const char *name,
                const char *param,
                UnitSetPropertiesMode mode) {
        int k;
        const char *value = NULL;

        assert(name);
        assert(u);
        assert(c);

        k = read_one_line_file("/run/systemd/manager/set-property-value", (char **)value);
        if (k < 0)
                log_error("Failed to read option value for unit property to set from file: %s.", strerror(-k));
                return 1;

        if (streq(param, "cpu-accounting")) {
                if (mode != UNIT_CHECK) {
                        bool b = parse_boolean(value);

                        c->cpu_accounting = b;
                        unit_write_drop_in_private(u, mode, name, b ? "CPUAccounting=yes" : "CPUAccounting=no");
                }

                return 1;
        } else if (streq(param, "cpu-shares")) {
                uint64_t u64;
                unsigned long ul;

                ul = (unsigned long) u64;

                if (u64 <= 0 || u64 != (uint64_t) ul)
                        return -EINVAL;

                ul = atoi(value);

                if (mode != UNIT_CHECK) {
                        c->cpu_shares = ul;
                        unit_write_drop_in_private_format(u, mode, name, "CPUShares=%lu", ul);
                }

                return 1;
        } else if (streq(param, "block-io-accounting")) {
                if (mode != UNIT_CHECK) {
                        bool b = parse_boolean(value);

                        c->blockio_accounting = b;
                        unit_write_drop_in_private(u, mode, name, b ? "BlockIOAccounting=yes" : "BlockIOAccounting=no");
                }

                return 1;
        } else if (streq(param, "block-io-weight")) {
                uint64_t u64;
                unsigned long ul;

                ul = (unsigned long) u64;

                if (u64 < 10 || u64 > 1000)
                        return -EINVAL;

                ul = atoi(value);

                if (mode != UNIT_CHECK) {
                        c->blockio_weight = ul;
                        unit_write_drop_in_private_format(u, mode, name, "BlockIOWeight=%lu", ul);
                }

                return 1;
        } else if (streq(name, "BlockIOReadBandwidth") || streq(name, "BlockIOWriteBandwidth")) {
                unsigned n = 0;
                bool read = true;
                const char *path;
                uint64_t u64;
                CGroupBlockIODeviceBandwidth *a;

                if (streq(name, "BlockIOWriteBandwidth"))
                        read = false;

                        if (mode != UNIT_CHECK) {
                                CGroupBlockIODeviceBandwidth *b;
                                bool exist = false;

                                LIST_FOREACH(device_bandwidths, b, c->blockio_device_bandwidths) {
                                        if (path_equal(path, b->path) && read == b->read) {
                                                a = b;
                                                exist = true;
                                                break;
                                        }
                                }

                                if (!exist) {
                                        a = new0(CGroupBlockIODeviceBandwidth, 1);
                                        if (!a)
                                                return -ENOMEM;

                                        a->read = read;
                                        a->path = strdup(path);
                                        if (!a->path) {
                                                free(a);
                                                return -ENOMEM;
                                        }
                                }

                                a->bandwidth = u64;

                                if (!exist)
                                        LIST_PREPEND(CGroupBlockIODeviceBandwidth, device_bandwidths,
                                                     c->blockio_device_bandwidths, a);
                        }

                        n++;

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        CGroupBlockIODeviceBandwidth *next;
                        size_t size = 0;

                        if (n == 0) {
                                LIST_FOREACH_SAFE(device_bandwidths, a, next, c->blockio_device_bandwidths)
                                        if (a->read == read)
                                                cgroup_context_free_blockio_device_bandwidth(c, a);
                        }

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                         if (read) {
                                fputs("BlockIOReadBandwidth=\n", f);
                                 LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths)
                                        if (a->read)
                                                fprintf(f, "BlockIOReadBandwidth=%s %" PRIu64 "\n", a->path, a->bandwidth);
                        } else {
                                fputs("BlockIOWriteBandwidth=\n", f);
                                LIST_FOREACH(device_bandwidths, a, c->blockio_device_bandwidths)
                                        if (!a->read)
                                                fprintf(f, "BlockIOWriteBandwidth=%s %" PRIu64 "\n", a->path, a->bandwidth);
                        }

                        fflush(f);
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;
        } else if (streq(name, "BlockIODeviceWeight")) {
                unsigned n = 0;
                const char *path;
                uint64_t u64;
                unsigned long ul;
                CGroupBlockIODeviceWeight *a;

                ul = (unsigned long) u64;
                if (ul < 10 || ul > 1000)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        CGroupBlockIODeviceWeight *b;
                        bool exist = false;

                        LIST_FOREACH(device_weights, b, c->blockio_device_weights) {
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        exist = true;
                                        break;
                                }
                        }

                        if (!exist) {
                                a = new0(CGroupBlockIODeviceWeight, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = strdup(path);
                                if (!a->path) {
                                        free(a);
                                        return -ENOMEM;
                                }
                        }

                        a->weight = ul;

                        if (!exist)
                                LIST_PREPEND(CGroupBlockIODeviceWeight, device_weights,
                                                c->blockio_device_weights, a);
                }
                n++;

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->blockio_device_weights)
                                        cgroup_context_free_blockio_device_weight(c, c->blockio_device_weights);
                        }

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("BlockIODeviceWeight=\n", f);
                        LIST_FOREACH(device_weights, a, c->blockio_device_weights)
                                fprintf(f, "BlockIODeviceWeight=%s %lu\n", a->path, a->weight);

                        fflush(f);
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;
        } else if (streq(param, "memory-accounting")) {
                if (mode != UNIT_CHECK) {
                        bool b = parse_boolean(value);

                        c->memory_accounting = b;
                        unit_write_drop_in_private(u, mode, name, b ? "MemoryAccounting=yes" : "MemoryAccounting=no");
                }

                return 1;
        } else if (streq(param, "memory-limit")) {
                if (mode != UNIT_CHECK) {
                        uint64_t limit = atoi(value);

                        c->memory_limit = limit;
                        unit_write_drop_in_private_format(u, mode, name, "%s=%" PRIu64, name, limit);
                }

                return 1;
        } else if (streq(param, "device-policy")) {
                const char *policy = value;
                CGroupDevicePolicy p;

                p = cgroup_device_policy_from_string(policy);
                if (p < 0)
                        return -EINVAL;

                if (mode != UNIT_CHECK) {
                        char *buf;

                        c->device_policy = p;

                        buf = strappenda("DevicePolicy=", policy);
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;
        } else if (streq(name, "DeviceAllow")) {
                unsigned n = 0;
                const char *path, *rwm;
                CGroupDeviceAllow *a;

                if (!path_startswith(path, "/dev")) {
                        log_error("DeviceAllow= requires device node");
                        return -EINVAL;
                }

                if (isempty(rwm))
                        rwm = "rwm";

                if (!in_charset(rwm, "rwm")) {
                        log_error("DeviceAllow= requires combination of rwm flags");
                        return -EINVAL;
                }

                if (mode != UNIT_CHECK) {
                        CGroupDeviceAllow *b;
                        bool exist = false;

                        LIST_FOREACH(device_allow, b, c->device_allow) {
                                if (path_equal(b->path, path)) {
                                        a = b;
                                        exist = true;
                                        break;
                                }
                        }

                        if (!exist) {
                                a = new0(CGroupDeviceAllow, 1);
                                if (!a)
                                        return -ENOMEM;

                                a->path = strdup(path);
                                if (!a->path) {
                                        free(a);
                                        return -ENOMEM;
                                }
                        }

                        a->r = !!strchr(rwm, 'r');
                        a->w = !!strchr(rwm, 'w');
                        a->m = !!strchr(rwm, 'm');

                        if (!exist)
                                LIST_PREPEND(CGroupDeviceAllow, device_allow, c->device_allow, a);
                }

                n++;

                if (mode != UNIT_CHECK) {
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *f = NULL;
                        size_t size = 0;

                        if (n == 0) {
                                while (c->device_allow)
                                        cgroup_context_free_device_allow(c, c->device_allow);
                        }

                        f = open_memstream(&buf, &size);
                        if (!f)
                                return -ENOMEM;

                        fputs("DeviceAllow=\n", f);
                        LIST_FOREACH(device_allow, a, c->device_allow)
                                fprintf(f, "DeviceAllow=%s %s%s%s\n", a->path, a->r ? "r" : "", a->w ? "w" : "", a->m ? "m" : "");

                        fflush(f);
                        unit_write_drop_in_private(u, mode, name, buf);
                }

                return 1;
        }

        return 0;
}

int prepare_reexecute(Manager *m, FILE **_f, FDSet **_fds, bool switching_root) {
        FILE *f = NULL;
        FDSet *fds = NULL;
        int r;

        assert(m);
        assert(_f);
        assert(_fds);

        r = manager_open_serialization(m, &f);
        if (r < 0) {
                log_error("Failed to create serialization file: %s", strerror(-r));
                goto fail;
        }

        /* Make sure nothing is really destructed when we shut down */
        m->n_reloading++;

        fds = fdset_new();
        if (!fds) {
                r = -ENOMEM;
                log_error("Failed to allocate fd set: %s", strerror(-r));
                goto fail;
        }

        r = manager_serialize(m, f, fds, switching_root);
        if (r < 0) {
                log_error("Failed to serialize state: %s", strerror(-r));
                goto fail;
        }

        if (fseeko(f, 0, SEEK_SET) < 0) {
                log_error("Failed to rewind serialization fd: %m");
                goto fail;
        }

        r = fd_cloexec(fileno(f), false);
        if (r < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization: %s", strerror(-r));
                goto fail;
        }

        r = fdset_cloexec(fds, false);
        if (r < 0) {
                log_error("Failed to disable O_CLOEXEC for serialization fds: %s", strerror(-r));
                goto fail;
        }

        *_f = f;
        *_fds = fds;

        return 0;

fail:
        fdset_free(fds);

        if (f)
                fclose(f);

        return r;
}

void regular_reexec(void) {
        const char **args = NULL;

        make_console_stdio();

        args[0] = "/sbin/init";
        execv(args[0], (char* const*) args);

        if (errno == ENOENT) {
                log_warning("No /sbin/init, trying fallback");

                args[0] = "/bin/sh";
                args[1] = NULL;
                execv(args[0], (char* const*) args);
                log_error("Failed to execute /bin/sh, giving up: %m");
                return;
        } else {
                log_warning("Failed to execute /sbin/init, giving up: %m");
                return;
        }
}

void reexec_procedure(char *switch_root_dir, char *switch_root_init,
                        FILE *serialization, FDSet *fds, const char *param,
                        Manager *m) {
        const char **args;
        int r;

        if (prepare_reexecute(m, &serialization, &fds, true) < 0)
                log_error("Failed to reexecute.");
                return;

        /* No serialization! */

        if (streq(param, "regular-reexec")) {
                regular_reexec();
        }

        /* Close and disarm the watchdog, so that the new
        * instance can reinitialize it, but doesn't get
        * rebooted while we do that */
        watchdog_close(true);

        if (switch_root_init) {
                args[0] = switch_root_init;
                execv(args[0], (char* const*) args);
                log_warning("Failed to execute configured init, trying fallback: %m");
        }

        /* Kill all remaining processes from the
        * initrd, but don't wait for them, so that we
        * can handle the SIGCHLD for them after
        * deserializing. */
        broadcast_signal(SIGTERM, false);

        /* And switch root */
        r = switch_root(switch_root_dir);
        if (r < 0)
                log_error("Failed to switch root, ignoring: %s", strerror(-r));
}

void shutdown_verb(void) {
        const char *shutdown_verb = NULL;
        const char * command_line[] = {
                SYSTEMD_SHUTDOWN_BINARY_PATH,
                shutdown_verb,
                NULL
        };
        char **env_block;

        if (detect_container(NULL) <= 0)
                cg_uninstall_release_agent(SYSTEMD_CGROUP_CONTROLLER);

        env_block = strv_copy(environ);
        watchdog_close(true);

        execve(SYSTEMD_SHUTDOWN_BINARY_PATH, (char **) command_line, env_block);
        free(env_block);
        log_error("Failed to execute shutdown binary, freezing: %m");

        if (getpid() == 1)
                freeze();
}
