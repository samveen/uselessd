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

#include "manager.h"
#include "util.h"
#include "strv.h"
#include "conf-parser.h"

#include "control-request.h"
#include "control-response-util.h"

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