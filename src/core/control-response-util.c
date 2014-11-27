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

#include "hashmap.h"
#include "install.h"
#include "log.h"
#include "job.h"
#include "unit.h"
#include "path-lookup.h"
#include "path-util.h"
#include "util.h"
#include "fileio.h"

#include "control-response-util.h"

UnitFileScope get_arg_scope(void) {
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

const char* get_arg_root(void) {
        int root;
        const char *p = NULL;

        root = read_one_line_file("/run/systemd/arg-root", (char **)&p);
        if (root < 0)
                return "unknown";

        return p;
}

bool test_runtime(void) {
        int r;
        _cleanup_free_ char *p = NULL;

        r = read_one_line_file("/run/systemd/arg-runtime", &p);
        if (r < 0)
                return false;

        return parse_boolean(p) > 0;
}

bool test_force(void) {
        int r;
        _cleanup_free_ char *p = NULL;

        r = read_one_line_file("/run/systemd/arg-force", &p);
        if (r < 0)
                return false;

        return parse_boolean(p) > 0;
}

/* TODO: carries_install_info.
* Fix encoding in UnitFileChange logging,
* or remove entirely.
* enable_sysv_units()...
* Don't repeat yourself! */
void get_default_target_tango(void) {
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
                log_info("%s", default_target);
}

void set_default_target_tango(void) {
        int setdef;
        const char *argroot;
        UnitFileScope argscope;
        int targetname;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        targetname = read_one_line_file("/run/systemd/manager/set-default-target", (char **)&p);
        if (targetname < 0)
                log_error("Failed to get default target to set: %s.", strerror(-targetname));

        setdef = unit_file_set_default(argscope, argroot, (char *)p, &changes, &n_changes);
        if (setdef < 0)
                log_error("Failed to set default target: %s.", strerror(-setdef));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void enable_unit_file_tango(void) {
        int enable;
        int unit_to_enable;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();
        argforce = test_force();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_enable = read_one_line_file("/run/systemd/manager/enable", (char **)&p);
        if (unit_to_enable < 0)
                log_error("Failed to get unit file to enable: %s.", strerror(-unit_to_enable));

        enable = unit_file_enable(argscope, argruntime, argroot, (char **)p, argforce, &changes, &n_changes);
        if (enable < 0)
                log_error("Failed to enable unit file: %s.", strerror(-enable));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void reenable_unit_file_tango(void) {
        int reenable;
        int unit_to_reenable;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();
        argforce = test_force();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_reenable = read_one_line_file("/run/systemd/manager/reenable", (char **)&p);
        if (unit_to_reenable < 0)
                log_error("Failed to get unit file to reenable: %s.", strerror(-unit_to_reenable));

        reenable = unit_file_reenable(argscope, argruntime, argroot, (char **)p, argforce, &changes, &n_changes);
        if (reenable < 0)
                log_error("Failed to reenable unit file: %s.", strerror(-reenable));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void disable_unit_file_tango(void) {
        int disable;
        int unit_to_disable;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_disable = read_one_line_file("/run/systemd/manager/disable", (char **)&p);
        if (unit_to_disable < 0)
                log_error("Failed to get unit file to disable: %s.", strerror(-unit_to_disable));

        disable = unit_file_disable(argscope, argruntime, argroot, (char **)p, &changes, &n_changes);
        if (disable < 0)
                log_error("Failed to disable unit file: %s.", strerror(-disable));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void preset_unit_file_tango(void) {
        int preset;
        int unit_to_preset;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();
        argforce = test_force();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_preset = read_one_line_file("/run/systemd/manager/preset", (char **)&p);
        if (unit_to_preset < 0)
                log_error("Failed to get unit file preset policy: %s.", strerror(-unit_to_preset));

        preset = unit_file_preset(argscope, argruntime, argroot, (char **)p, argforce, &changes, &n_changes);
        if (preset < 0)
                log_error("Failed to apply unit file preset policy: %s.", strerror(-preset));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void mask_unit_file_tango(void) {
        int mask;
        int unit_to_mask;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();
        argforce = test_force();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_mask = read_one_line_file("/run/systemd/manager/mask", (char **)&p);
        if (unit_to_mask < 0)
                log_error("Failed to get unit file to mask: %s.", strerror(-unit_to_mask));

        mask = unit_file_mask(argscope, argruntime, argroot, (char **)p, argforce, &changes, &n_changes);
        if (mask < 0)
                log_error("Failed to mask unit file: %s.", strerror(-mask));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void unmask_unit_file_tango(void) {
        int unmask;
        int unit_to_unmask;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_unmask = read_one_line_file("/run/systemd/manager/unmask", (char **)&p);
        if (unit_to_unmask < 0)
                log_error("Failed to get unit file to unmask: %s.", strerror(-unit_to_unmask));

        unmask = unit_file_unmask(argscope, argruntime, argroot, (char **)p, &changes, &n_changes);
        if (unmask < 0)
                log_error("Failed to unmask unit file: %s.", strerror(-unmask));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void link_unit_file_tango(void) {
        int link;
        int unit_to_link;
        const char *argroot;
        UnitFileScope argscope;
        bool argruntime;
        bool argforce;
        const char *p = NULL;

        UnitFileChange *changes;
        unsigned n_changes = 0, ic;

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argruntime = test_runtime();
        argforce = test_force();

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        unit_to_link = read_one_line_file("/run/systemd/manager/link", (char **)&p);
        if (unit_to_link < 0)
                log_error("Failed to get unit file to link: %s.", strerror(-unit_to_link));

        link = unit_file_link(argscope, argruntime, argroot, (char **)p, argforce, &changes, &n_changes);
        if (link < 0)
                log_error("Failed to link unit file: %s.", strerror(-link));

        for (ic = 0; ic < n_changes; ic++) {
                if (changes[ic].type == UNIT_FILE_SYMLINK)
                        log_info("ln -s '%s' '%s'", changes[ic].source, changes[ic].path);
                else
                        log_info("rm '%s'", changes[ic].path);
        }
}

void is_unit_file_enabled(void) {
        UnitFileState state;
        UnitFileScope argscope;
        const char *argroot;
        int isen;
        const char *n = NULL;

        isen = read_one_line_file("/run/systemd/manager/is-enabled", (char **)&n);
        if (isen < 0)
                log_error("Failed to get unit file state: %s.", strerror(-isen));

        argroot = get_arg_root();
        if (streq("unknown", argroot))
                log_error("Failed to get unit file root from /run/systemd/arg-root.");

        argscope = get_arg_scope();
        if (argscope < 0)
                log_error("Failed to get unit file scope from /run/systemd/arg-scope.");

        state = unit_file_get_state(argscope, argroot, n);
        if (state < 0)
                log_error("Failed to get state for unit file.");

        puts(unit_file_state_to_string(state));
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
