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

#include <sys/reboot.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <stdint.h>

#include "fifo-control.h"
#include "log.h"
#include "manager.h"
#include "job.h"
#include "unit.h"
#include "hashmap.h"
#include "path-util.h"
#include "install.h"
#include "util.h"
#include "fileio.h"
#include "strv.h"
#include "conf-parser.h"
#include "path-lookup.h"
#include "dbus-common.h" /* struct unit_info */

static UnitFileScope get_arg_scope(void) {
        int scope;
        _cleanup_free_ char *p = NULL;

        scope = read_one_line_file("/run/systemd/arg-scope", &p);
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

static const char* get_arg_root(void) {
        int root;
        const char *p = NULL;

        root = read_one_line_file("/run/systemd/arg-root", (char **)&p);
        if (root < 0)
                return "unknown";

        return p;
}

static void output_unit_file_list(const UnitFileList *units, unsigned c) {
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

static void list_unit_files(void) {
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

static int compare_unit_info(const void *a, const void *b) {
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

static void output_units_list(const struct unit_info *unit_infos, unsigned c) {
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

static void list_jobs_print(struct job_info* jobs, size_t n) {
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

void create_control_fifo(void) {
        int c;
        int d;

        c = mkfifo("/run/systemd/fifoctl", 0644);
        if (c < 0) {
                log_error("Creation of fifoctl IPC server endpoint failed: %s.", strerror(-c));
                return;
        }

        d = mkfifo("/run/systemd/fifoout", 0644);
        if (d < 0) {
                log_error("Creation of fifoout IPC client endpoint failed: %s.", strerror(-d));
                return;
        }

        return;
}

void unlink_control_fifo(void) {
        int r;
        int k;

        r = unlink("/run/systemd/fifoctl");
        if (r < 0) {
                log_error("Unlinking the fifoctl IPC server endpoint failed: %s.", strerror(-r));
                return;
        }

        k = unlink("/run/systemd/fifoout");
        if (k < 0) {
                log_error("Unlinking the fifoout IPC client endpoint failed: %s.", strerror(-k));
                return;
        }

        return;
}

/* TODO: make things like arg_root, arg_scope, etc.
 * user-configurable from systemctl... much of this functionality
 * should probably be moved later on. Perhaps store values in files. */
void fifo_control_loop(void) {
        int f, r, d;
        char fifobuf[BUFSIZ];
        Manager *m = NULL;

        d = manager_new(SYSTEMD_SYSTEM, true, &m);
        assert_se(d >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        create_control_fifo();

        f = open("/run/systemd/fifoctl", O_RDWR);
        if (f < 0) {
                log_error("Opening fifoctl IPC endpoint failed: %s.", strerror(-f));
        }

        for (;;) {
                r = read(f, fifobuf, BUFSIZ);

                if (r == -1) {
                        log_error("Failed to read from fifoctl IPC endpoint: %s.", strerror(-r));
                }

                if (streq("test", fifobuf)) {
                        log_info("Badabing.\n");
                } else if (streq("reld", fifobuf)) {
                        /*m->exit_code = MANAGER_RELOAD;*/
                        if (kill(getpid(), SIGHUP) < 0)
                                log_error("kill() failed: %m");
                                return;
                } else if (streq("rexc", fifobuf)) {
                        /*m->exit_code = MANAGER_REEXECUTE;*/
                        if (kill(getpid(), SIGTERM) < 0)
                                log_error("kill() failed: %m");
                                return;
                } else if (streq("exit", fifobuf)) {
                        if (m->running_as == SYSTEMD_SYSTEM && getpid() == 1)
                                log_error("Exit is only supported for user service managers and non-PID1 system managers.");

                        /*m->exit_code = MANAGER_EXIT;*/
                        if (kill(getpid(), SIGINT) < 0)
                                log_error("kill() failed: %m");
                                return;
                } else if (streq("gdtr", fifobuf)) {
                        int def;
                        UnitFileScope argscope;
                        const char *argroot;
                        _cleanup_free_ char *default_target = NULL;

                        argroot = get_arg_root();
                        if (streq("unknown", argroot))
                                log_error("Failed to get unit file root from /run/systemd/arg-root.");

                        argscope = get_arg_scope();
                        if (argscope < 0)
                                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

                        def = unit_file_get_default(argscope, (const char *)argroot, &default_target);
                        if (default_target)
                                log_info("Default target: %s", default_target);
                } else if (streq("lenv", fifobuf)) {
                        /* UB */
                        log_info("%s", (char *)m->environment);
                } else if (streq("lsuf", fifobuf)) {
                        /* currently unsorted */
                        list_unit_files();
                /* TODO: free jobs */
                } else if (streq("lsjb", fifobuf)) {
                        Iterator i;
                        Job *j;
                        struct job_info *jobs = NULL;
                        size_t size = 0, used = 0;

                        HASHMAP_FOREACH(j, m->jobs, i) {
                                const char *name, *state, *type;
                                uint32_t id;

                                id = (uint32_t) j->id;
                                state = job_state_to_string(j->state);
                                type = job_type_to_string(j->type);

                                if (!GREEDY_REALLOC(jobs, size, used + 1)) {
                                        log_oom();
                                }

                                jobs[used++] = (struct job_info) { id,
                                                                strdup(name),
                                                                strdup(type),
                                                                strdup(state) };

                                if (!jobs[used-1].name || !jobs[used-1].type || !jobs[used-1].state) {
                                        log_oom();
                                }

                        }

                        list_jobs_print(jobs, used);
                } else if (streq("lsun", fifobuf)) {
                        Iterator i;
                        Unit *u;
                        const char *k;
                        _cleanup_free_ struct unit_info *unit_infos = NULL;
                        unsigned cnt = 0;

                        HASHMAP_FOREACH_KEY(u, k, m->units, i) {
                                char *u_path, *j_path;
                                const char *description, *load_state, *active_state, *sub_state, *sjob_type, *following;
                                uint32_t job_id;
                                Unit *follow;

                                if (k != u->id)
                                        continue;

                                description = unit_description(u);
                                load_state = unit_load_state_to_string(u->load_state);
                                active_state = unit_active_state_to_string(unit_active_state(u));
                                sub_state = unit_sub_state_to_string(u);

                                follow = unit_following(u);
                                following = follow ? follow->id : "";

                                if (u->job) {
                                        job_id = (uint32_t) u->job->id;

                                        sjob_type = job_type_to_string(u->job->type);
                                } else {
                                        job_id = 0;
                                        j_path = u_path;
                                        sjob_type = "";
                                }

                                free(u_path);
                                if (u->job)
                                        free(j_path);
                        }

                        qsort(unit_infos, cnt, sizeof(struct unit_info), compare_unit_info);

                        output_units_list(unit_infos, cnt);
                /* These would be better served by isolating to targets.
                 * Be sure to integrate send_shutdownd() utmp record
                 * writing in full versions. */
                } else if (streq("poff", fifobuf)) {
                        reboot(RB_ENABLE_CAD);
                        log_info("Powering off.");
                        reboot(RB_POWER_OFF);
                        goto finish;
                } else if (streq("rebt", fifobuf)) {
                        reboot(RB_ENABLE_CAD);
                        log_info("Rebooting.");
                        reboot(RB_AUTOBOOT);
                        goto finish;
                } else if (streq("halt", fifobuf)) {
                        reboot(RB_ENABLE_CAD);
                        log_info("Halting.");
                        reboot(RB_HALT_SYSTEM);
                        goto finish;
                } else if (streq("kxec", fifobuf)) {
                        /* todo */
                        break;
                } else if (streq("refa", fifobuf)) {
                        manager_reset_failed(m);
                }

        }
finish:
        close(f);
        unlink_control_fifo();
}
