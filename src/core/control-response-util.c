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
#include "cgroup.h"
#include "fileio.h"
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
void unit_file_operation_tango(const char *param) {
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        UnitFileState state;
        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

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
                char *default_target = NULL;

                r = unit_file_get_default(argscope, argroot, &default_target);
                if (default_target)
                        log_info("%s", default_target);

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

                puts(unit_file_state_to_string(state));

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

        max_id_len = sizeof("UNIT FILE")-1;
        state_cols = sizeof("STATE")-1;
        for (u = units; u < units + c; u++) {

                max_id_len = MAX(max_id_len, strlen(path_get_file_name(u->path)));
                state_cols = MAX(state_cols, strlen(unit_file_state_to_string(u->state)));
        }

        id_cols = max_id_len;

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

                printf("%-*s %s%-*s%s\n",
                       id_cols, e ? e : id,
                       on, state_cols, unit_file_state_to_string(u->state), off);
        }

        printf("\n%u unit files listed.\n", n_shown);
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

int compare_unit_info(const void *a, const void *b) {
        const char *d1, *d2;
        const struct unit_info *u = a, *v = b;

        d1 = strrchr(u->id, '.');
        d2 = strrchr(v->id, '.');

        if (d1 && d2) {
                int r;

                r = strcasecmp(d1, d2);
                if (r != 0)
                        return r;
        }

        return strcasecmp(u->id, v->id);
}

void output_units_list(const struct unit_info *unit_infos, unsigned c) {
        unsigned id_len, max_id_len, active_len, sub_len, job_len, desc_len, n_shown = 0;
        unsigned basic_len;
        const struct unit_info *u;
                        const char *on_loaded, *off_loaded, *on = "";
                const char *on_active, *off_active, *off = "";
        int job_count = 0;

        max_id_len = sizeof("UNIT")-1;
        active_len = sizeof("ACTIVE")-1;
        sub_len = sizeof("SUB")-1;
        job_len = sizeof("JOB")-1;
        desc_len = 0;

        for (u = unit_infos; u < unit_infos + c; u++) {
                max_id_len = MAX(max_id_len, strlen(u->id));
                active_len = MAX(active_len, strlen(u->active_state));
                sub_len = MAX(sub_len, strlen(u->sub_state));
                if (u->job_id != 0) {
                        job_len = MAX(job_len, strlen(u->job_type));
                        job_count++;
                }
        }

                id_len = MIN(max_id_len, 25u);
                basic_len = 5 + id_len + 5 + active_len + sub_len;
                if (job_count)
                        basic_len += job_len + 1;
                if (basic_len < (unsigned) columns()) {
                        unsigned extra_len, incr;
                        extra_len = columns() - basic_len;
                        /* Either UNIT already got 25, or is fully satisfied.
                         * Grant up to 25 to DESC now. */
                        incr = MIN(extra_len, 25u);
                        desc_len += incr;
                        extra_len -= incr;
                        /* split the remaining space between UNIT and DESC,
                         * but do not give UNIT more than it needs. */
                        if (extra_len > 0) {
                                incr = MIN(extra_len / 2, max_id_len - id_len);
                                id_len += incr;
                                desc_len += extra_len - incr;
                        } else
                                id_len = max_id_len;
                }

        for (u = unit_infos; u < unit_infos + c; u++) {
                _cleanup_free_ char *e = NULL;

                if (!n_shown) {
                        printf("%-*s %-6s %-*s %-*s ", id_len, "UNIT", "LOAD",
                               active_len, "ACTIVE", sub_len, "SUB");
                        if (job_count)
                                printf("%-*s ", job_len, "JOB");
                        printf("%s\n", "DESCRIPTION");
                }

                n_shown++;

                if (streq(u->load_state, "error") ||
                    streq(u->load_state, "not-found")) {
                        on_loaded = on = ansi_highlight_red();
                        off_loaded = off = ansi_highlight_off();
                } else
                        on_loaded = off_loaded = "";

                if (streq(u->active_state, "failed")) {
                        on_active = on = ansi_highlight_red();
                        off_active = off = ansi_highlight_off();
                } else
                        on_active = off_active = "";

                e = ellipsize(u->id, id_len, 33);

                printf("%s%-*s%s %s%-6s%s %s%-*s %-*s%s %-*s",
                       on, id_len, e ? e : u->id, off,
                       on_loaded, u->load_state, off_loaded,
                       on_active, active_len, u->active_state,
                       sub_len, u->sub_state, off_active,
                       job_count ? job_len + 1 : 0, u->job_id ? u->job_type : "");
                if (desc_len > 0)
                        printf("%.*s\n", desc_len, u->description);
                else
                        printf("%s\n", u->description);
        }

                if (n_shown) {
                        printf("\nLOAD   = Reflects whether the unit definition was properly loaded.\n"
                               "ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
                               "SUB    = The low-level unit activation state, values depend on unit type.\n");
                        if (job_count)
                                printf("JOB    = Pending job for the unit.\n");
                        puts("");
                        on = ansi_highlight();
                        off = ansi_highlight_off();
                } else {
                        on = ansi_highlight_red();
                        off = ansi_highlight_off();
                }

                        printf("%s%u loaded units listed.%s\n"
                               "To show all installed unit files use 'systemctl list-unit-files'.\n",
                               on, n_shown, off);
}

void list_jobs_print(struct job_info* jobs, size_t n) {
        size_t i;
        struct job_info *j;
        const char *on, *off;
        bool shorten = false;

        assert(n == 0 || jobs);

        if (n == 0) {
                on = ansi_highlight_green();
                off = ansi_highlight_off();

                printf("%sNo jobs running.%s\n", on, off);
                return;
        }

        {
                /* JOB UNIT TYPE STATE */
                unsigned l0 = 3, l1 = 4, l2 = 4, l3 = 5;

                for (i = 0, j = jobs; i < n; i++, j++) {
                        assert(j->name && j->type && j->state);
                        l0 = MAX(l0, DECIMAL_STR_WIDTH(j->id));
                        l1 = MAX(l1, strlen(j->name));
                        l2 = MAX(l2, strlen(j->type));
                        l3 = MAX(l3, strlen(j->state));
                }

                if (l0 + 1 + l1 + l2 + 1 + l3 > columns()) {
                        l1 = MAX(33u, columns() - l0 - l2 - l3 - 3);
                        shorten = true;
                }

                if (on_tty())
                        printf("%*s %-*s %-*s %-*s\n",
                               l0, "JOB",
                               l1, "UNIT",
                               l2, "TYPE",
                               l3, "STATE");

                for (i = 0, j = jobs; i < n; i++, j++) {
                        _cleanup_free_ char *e = NULL;

                        if (streq(j->state, "running")) {
                                on = ansi_highlight();
                                off = ansi_highlight_off();
                        } else
                                on = off = "";

                        e = shorten ? ellipsize(j->name, l1, 33) : NULL;
                        printf("%*u %s%-*s%s %-*s %s%-*s%s\n",
                               l0, j->id,
                               on, l1, e ? e : j->name, off,
                               l2, j->type,
                               on, l3, j->state, off);
                }
        }

        on = ansi_highlight();
        off = ansi_highlight_off();

        if (on_tty())
                printf("\n%s%zu jobs listed%s.\n", on, n, off);
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
                        CGroupBlockIODeviceBandwidth *a;
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
                        CGroupBlockIODeviceWeight *a;
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

        } else if (streq(param, "DevicePolicy")) {
                const char *policy;
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
                        CGroupDeviceAllow *a;
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
