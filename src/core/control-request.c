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
#include "snapshot.h"
#include "util.h"
#include "env-util.h"
#include "path-util.h"
#include "strv.h"
#include "job.h"
#include "conf-parser.h"
#include "utmp-wtmp.h"
#include "kill.h"
#include "fileio.h"
#include "special.h"

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

/* Much of this should likely be moved and refactored later on. */
void fifo_control_loop(void) {
        int f, r, d;
        char fifobuf[BUFSIZ];
        Manager *m;
        usec_t when;
        when = now(CLOCK_REALTIME) + USEC_PER_MINUTE;

        d = manager_new(SYSTEMD_SYSTEM, true, &m);
        assert_se(d >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);

        assert(m->environment);

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

                if (streq("foobr", fifobuf)) {
                        Unit *u;
                        u = manager_get_unit(m, "default.target");
                        if (u) log_info("yh");
                        log_info("Badabing.\n");
                } else if (streq("rload", fifobuf)) {
                        /*m->exit_code = MANAGER_RELOAD;*/
                        if (kill(getpid(), SIGHUP) < 0)
                                log_error("kill() failed: %m");
                                return;
                } else if (streq("rexec", fifobuf)) {
                        /*m->exit_code = MANAGER_REEXECUTE;*/
                        if (kill(getpid(), SIGTERM) < 0)
                                log_error("kill() failed: %m");
                                return;
                } else if (streq("mexit", fifobuf)) {
                        if (m->running_as == SYSTEMD_SYSTEM && getpid() == 1)
                                log_error("Exit is only supported for user service managers and non-PID1 system managers.");

                        /*m->exit_code = MANAGER_EXIT;*/
                        if (kill(getpid(), SIGINT) < 0)
                                log_error("kill() failed: %m");
                                return;
                } else if (streq("getdt", fifobuf)) {
                        unit_file_operation_tango("get-default-target");
                } else if (streq("lsenv", fifobuf)) {
                        strv_print(m->environment);
                } else if (streq("stenv", fifobuf)) {
                        /* TODO: strv env is valid check */
                        int j;
                        char **w = NULL;
                        char *e = NULL;

                        touch(MANAGER_OPERATION_LOCKFILE);

                        j = read_one_line_file("/run/systemd/manager/set-environment", &e);
                        if (j < 0)
                                log_error("Failed to get environment variable to set.");

                        w = strv_env_set(m->environment, e);
                        if (!w)
                                log_oom();

                        unlink(MANAGER_OPERATION_LOCKFILE);

                        strv_free(m->environment);
                        m->environment = w;
                } else if (streq("usenv", fifobuf)) {
                        /* TODO: strv env is valid check */
                        int j;
                        char **w = NULL;
                        char *e = NULL;

                        touch(MANAGER_OPERATION_LOCKFILE);

                        j = read_one_line_file("/run/systemd/manager/unset-environment", &e);
                        if (j < 0)
                                log_error("Failed to get environment variable to set.");

                        w = strv_env_unset(m->environment, e);
                        if (!w)
                                log_oom();

                        unlink(MANAGER_OPERATION_LOCKFILE);
                } else if (streq("lsunf", fifobuf)) {
                        /* currently unsorted */
                        list_unit_files();
                /* TODO: free jobs */
                } else if (streq("lsjob", fifobuf)) {
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
                } else if (streq("cnjob", fifobuf)) {
                        /* TODO: add overflow/errno checks */
                        Job *j;
                        int jobfile;
                        uint32_t id;
                        _cleanup_free_ char *p = NULL;

                        jobfile = read_one_line_file("/run/systemd/manager/cancel-job-id", &p);
                        id = atoi(p);

                        j = manager_get_job(m, id);
                        if (!j) {
                                log_error("Job %u does not exist.", (unsigned) id);
                                break;
                        }

                        job_finish_and_invalidate(j, JOB_CANCELED, true);
                } else if (streq("clrjb", fifobuf)) {
                        manager_clear_jobs(m);
                } else if (streq("lsuni", fifobuf)) {
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
                 * Also make sure char *m is a wall message later on. */
                } else if (streq("powff", fifobuf)) {
                        int sd;
                        int ups;
                        const char *msg = "ayylmao";

                        if (geteuid() != 0)
                                log_error("Must be root.");

                        sd = send_shutdownd(when, 'P', false, false, msg);
                        if (sd < 0) {
                                log_warning("Failed to talk to shutdownd, proceeding with immediate shutdown: %s",
                                        strerror(-sd));
                        } else {
                                char date[FORMAT_TIMESTAMP_MAX];

                                log_info("Shutdown scheduled for %s, use 'shutdown -c' to cancel.",
                                        format_timestamp(date, sizeof(date), when));
                        }

                        ups = utmp_put_shutdown();
                        if (ups < 0)
                                log_warning("Failed to write utmp record: %s", strerror(-ups));

                        sync();

                        reboot(RB_ENABLE_CAD);
                        log_info("Powering off.");
                        reboot(RB_POWER_OFF);

                        goto finish;
                } else if (streq("rboot", fifobuf)) {
                        int sd;
                        int ups;
                        const char *msg = "ayylmao";

                        if (geteuid() != 0)
                                log_error("Must be root.");

                        sd = send_shutdownd(when, 'r', false, false, msg);
                        if (sd < 0) {
                                log_warning("Failed to talk to shutdownd, proceeding with immediate shutdown: %s",
                                        strerror(-sd));
                        } else {
                                char date[FORMAT_TIMESTAMP_MAX];

                                log_info("Shutdown scheduled for %s, use 'shutdown -c' to cancel.",
                                        format_timestamp(date, sizeof(date), when));
                        }

                        ups = utmp_put_shutdown();
                        if (ups < 0)
                                log_warning("Failed to write utmp record: %s", strerror(-ups));

                        sync();

                        reboot(RB_ENABLE_CAD);
                        log_info("Rebooting.");
                        reboot(RB_AUTOBOOT);

                        goto finish;
                } else if (streq("halts", fifobuf)) {
                        int sd;
                        int ups;
                        const char *msg = "ayylmao";

                        if (geteuid() != 0)
                                log_error("Must be root.");

                        sd = send_shutdownd(when, 'H', false, false, msg);
                        if (sd < 0) {
                                log_warning("Failed to talk to shutdownd, proceeding with immediate shutdown: %s",
                                        strerror(-sd));
                        } else {
                                char date[FORMAT_TIMESTAMP_MAX];

                                log_info("Shutdown scheduled for %s, use 'shutdown -c' to cancel.",
                                        format_timestamp(date, sizeof(date), when));
                        }

                        ups = utmp_put_shutdown();
                        if (ups < 0)
                                log_warning("Failed to write utmp record: %s", strerror(-ups));

                        sync();

                        reboot(RB_ENABLE_CAD);
                        log_info("Halting.");
                        reboot(RB_HALT_SYSTEM);

                        goto finish;
                } else if (streq("kexec", fifobuf)) {
                        int sd;
                        const char *msg = "ayylmao";

                        if (geteuid() != 0)
                                log_error("Must be root.");

                        sd = send_shutdownd(when, 'K', false, false, msg);
                        if (sd < 0) {
                                log_warning("Failed to talk to shutdownd, proceeding with immediate shutdown: %s",
                                        strerror(-sd));
                        } else {
                                char date[FORMAT_TIMESTAMP_MAX];

                                log_info("Shutdown scheduled for %s, use 'shutdown -c' to cancel.",
                                        format_timestamp(date, sizeof(date), when));
                        }

                        m->exit_code = MANAGER_KEXEC;

                        break;
                } else if (streq("deflt", fifobuf)) {
                        Job *j;
                        manager_add_job_by_name(m, JOB_START, SPECIAL_DEFAULT_TARGET, JOB_ISOLATE, true, &j);
                /* TODO: print wall messages */
                } else if (streq("rescu", fifobuf)) {
                        Job *j;
                        manager_add_job_by_name(m, JOB_START, SPECIAL_RESCUE_TARGET, JOB_ISOLATE, true, &j);
                } else if (streq("emerg", fifobuf)) {
                        Job *j;
                        manager_add_job_by_name(m, JOB_START, SPECIAL_EMERGENCY_TARGET, JOB_ISOLATE, true, &j);
                } else if (streq("suspn", fifobuf)) {
                        manager_start_target(m, SPECIAL_SUSPEND_TARGET, JOB_REPLACE_IRREVERSIBLY);
                } else if (streq("hiber", fifobuf)) {
                        manager_start_target(m, SPECIAL_HIBERNATE_TARGET, JOB_REPLACE_IRREVERSIBLY);
                } else if (streq("hybsl", fifobuf)) {
                        manager_start_target(m, SPECIAL_HYBRID_SLEEP_TARGET, JOB_REPLACE_IRREVERSIBLY);
                } else if (streq("swirt", fifobuf)) {
                        const char *switch_root = NULL, *switch_root_init = NULL;
                        int getsri;
                        int getsrp;
                        char *u, *v = NULL;
                        bool good;

                        getsrp = read_one_line_file("/run/systemd/manager/switch-root-path", (char **)switch_root);
                        if (getsrp < 0)
                                log_error("Failed to read switch root path from file: %s.", strerror(-getsrp));

                        getsri = read_one_line_file("/run/systemd/manager/switch-root-init", (char **)switch_root_init);
                        if (getsri < 0)
                                log_error("Failed to read switch root init from file: %s.", strerror(-getsri));

                        if (path_equal(switch_root, "/") || !path_is_absolute(switch_root))
                                log_error("Trying to switch root on / or path is not absolute.");

                        if (!isempty(switch_root_init) && !path_is_absolute(switch_root_init))
                                log_error("Init path is not absolute.");

                        if (m->running_as != SYSTEMD_SYSTEM) {
                                log_error("Switching root is only supported for system managers.");
                        }

                        if (isempty(switch_root_init)) {
                                good = path_is_os_tree(switch_root);
                                if (!good)
                                        log_error("Not switching root: %s does not seem to be an OS tree. /etc/os-release is missing.",
                                                switch_root);
                        } else {
                                _cleanup_free_ char *p = NULL;

                                p = strjoin(switch_root, "/", switch_root_init, NULL);
                                if (!p)
                                        log_oom();

                                good = access(p, X_OK) >= 0;
                                if (!good)
                                        log_error("Not switching root: cannot execute new init %s", p);
                        }
                        if (!good)
                                log_error("Switch root sanity checks failed.");

                        u = strdup(switch_root);
                        if (!u)
                                log_oom();

                        if (!isempty(switch_root_init)) {
                                v = strdup(switch_root_init);
                                if (!v) {
                                        free(u);
                                        log_oom();
                                } else {
                                        v = NULL;
                                }
                        }

                        free(m->switch_root);
                        free(m->switch_root_init);
                        m->switch_root = u;
                        m->switch_root_init = v;

                        m->exit_code = MANAGER_SWITCH_ROOT;
                } else if (streq("resfa", fifobuf)) {
                        manager_reset_failed(m);
                } else if (streq("enabl", fifobuf)) {
                        unit_file_operation_tango("enable");
                } else if (streq("disab", fifobuf)) {
                        unit_file_operation_tango("disable");
                } else if (streq("isena", fifobuf)) {
                        unit_file_operation_tango("is-enabled");
                } else if (streq("reena", fifobuf)) {
                        unit_file_operation_tango("reenable");
                } else if (streq("prset", fifobuf)) {
                        unit_file_operation_tango("preset");
                } else if (streq("maskf", fifobuf)) {
                        unit_file_operation_tango("mask");
                } else if (streq("umskf", fifobuf)) {
                        unit_file_operation_tango("unmask");
                } else if (streq("linkf", fifobuf)) {
                        unit_file_operation_tango("link");
                } else if (streq("setdt", fifobuf)) {
                        unit_file_operation_tango("set-default-target");
                } else if (streq("mksnp", fifobuf)) {
                        int name;
                        _cleanup_free_ char *p = NULL;
                        int k;
                        bool cleanup = false;
                        Snapshot *s;

                        touch(MANAGER_OPERATION_LOCKFILE);
                        name = read_one_line_file("/run/systemd/manager/create-snapshot", &p);
                        if (name < 0)
                                log_error("Failed to get snapshot file name.");

                        k = snapshot_create(m, p, cleanup, &s);
                        if (k < 0)
                                log_error("Snapshot creation failed: %s.", strerror(-k));
                        unlink(MANAGER_OPERATION_LOCKFILE);

                } else if (streq("rmsnp", fifobuf)) {
                        /* ltrace shows only file read. */
                        int name;
                        Unit *u;
                        _cleanup_free_ char *p = NULL;

                        touch(MANAGER_OPERATION_LOCKFILE);
                        name = read_one_line_file("/run/systemd/manager/remove-snapshot", &p);
                        if (name < 0)
                                log_error("Failed to get snapshot name to remove.");

                        u = manager_get_unit(m, p);
                        if (!u) {
                                log_error("Unit %s does not exist.", p);
                        }

                        if (u->type != UNIT_SNAPSHOT) {
                                log_error("Unit %s is not a snapshot.", p);
                        }

                        snapshot_remove(SNAPSHOT(u));
                        unlink(MANAGER_OPERATION_LOCKFILE);
                } else if (streq("start", fifobuf)) {
                        /* This is a generic operation that adds jobs. */
                        Job *j;
                        JobType type;
                        JobMode mode;
                        int k;
                        int getname;
                        char *name;

                        getname = read_one_line_file("/run/systemd/manager/launch", &name);
                        if (getname < 0)
                                log_error("Failed to get unit name to perform job operation on.");

                        type = get_arg_job_type();
                        mode = get_arg_job_mode();

                        k = manager_add_job_by_name(m, type, name, mode, true, &j);
                        if (k < 0)
                                log_error("Adding job failed: %s", strerror(-k));
                } else if (streq("pkill", fifobuf)) {
                        char *name;
                        int k, q;
                        int32_t signo;
                        Unit *u;
                        KillWho who;

                        signo = get_kill_signal();
                        who = get_kill_who();

                        q = read_one_line_file("/run/systemd/manager/kill", &name);
                        if (q < 0)
                                log_error("Failed to get unit to kill: %s.", strerror(-q));

                        u = manager_get_unit(m, name);
                        if (!u) {
                                log_error("Unit %s is not loaded.", name);
                                break;
                        }

                        k = unit_kill(u, who, signo);
                        if (k < 0)
                                log_error("Failed to send kill signal to unit: %s.", strerror(-k));
                } else if (streq("isact", fifobuf)) {
                        const char *name = "rsync.service";
                        Unit *u;
                        const char *active_state;

                        u = manager_get_unit(m, name);
                        if (!u)
                                log_error("Unit %s is not loaded.", name);
                                break;

                        active_state = unit_active_state_to_string(unit_active_state(u));
                        puts(active_state);
                }

        }
finish:
        close(f);
        unlink_control_fifo();
}
