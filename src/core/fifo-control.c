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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#include "fifo-control.h"
#include "log.h"
#include "manager.h"
#include "unit.h"
#include "install.h"
#include "util.h"

void fifo_control_loop(void) {
        int c, f, r;
        char fifobuf[BUFSIZ];
        Manager *m;

        c = mkfifo("/run/systemd/fifoctl", 0644);
        if (c < 0) {
                log_error("Creation of fifoctl IPC endpoint failed: %s.", strerror(-c));
        }

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
                        m->exit_code = MANAGER_RELOAD;
                } else if (streq("rexc", fifobuf)) {
                        m->exit_code = MANAGER_REEXECUTE;
                } else if (streq("exit", fifobuf)) {
                        if (m->running_as == SYSTEMD_SYSTEM)
                                log_error("Exit is only supported for user service managers.");

                        m->exit_code = MANAGER_EXIT;
                } else if (streq("gdtr", fifobuf)) {
                        int def;
                        _cleanup_free_ char *default_target = NULL;

                        def = unit_file_get_default(UNIT_FILE_GLOBAL, NULL, &default_target);
                        log_info("Default target: %u", def);
                }

        }

finish:
        close(f);
        unlink("/run/systemd/fifoctl");
}