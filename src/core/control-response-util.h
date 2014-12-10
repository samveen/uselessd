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

#include <stdlib.h>
#include <stdbool.h>

#include "install.h"
#include "job.h"
#include "util.h"
#include "cgroup.h"
#include "kill.h"

struct unit_info {
        const char *id;
        const char *description;
        const char *load_state;
        const char *active_state;
        const char *sub_state;
        const char *following;
        const char *unit_path;
        uint32_t job_id;
        const char *job_type;
        const char *job_path;
};

struct job_info {
        uint32_t id;
        char *name, *type, *state;
};

UnitFileScope get_arg_scope(void);
const char* get_arg_root(void);
JobMode get_arg_job_mode(void);
JobType get_arg_job_type(void);
KillWho get_kill_who(void);
int32_t get_kill_signal(void);
bool test_runtime(void);
bool test_force(void);
void unit_file_operation_tango(const char *param);
void output_unit_file_list(const UnitFileList *units, unsigned c);
void list_unit_files(void);
int compare_unit_info(const void *a, const void *b);
void output_units_list(const struct unit_info *unit_infos, unsigned c);
void list_jobs_print(struct job_info* jobs, size_t n);
void unit_systemctl_status_print(Unit *u);
int send_shutdownd(usec_t t, char mode, bool dry_run, bool warn, const char *message);
int cgroup_set_property(Unit *u, CGroupContext *c, const char *name,
                        const char *param, UnitSetPropertiesMode mode);
int prepare_reexecute(Manager *m, FILE **_f, FDSet **_fds, bool switching_root);
void regular_reexec(void);
void reexec_procedure(char *switch_root_dir, char *switch_root_init,
                        FILE *serialization, FDSet *fds, const char *param,
                        Manager *m);
void shutdown_verb(void);
