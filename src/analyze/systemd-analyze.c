/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010-2013 Lennart Poettering
  Copyright 2013 Simon Peeters

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


#include <stdio.h>
/*
#include <stdlib.h>
#include <getopt.h>
#include <locale.h>
#include <sys/utsname.h>
#include <fnmatch.h>

#include "install.h"
#include "log.h"
#include "dbus-common.h"
#include "build.h"
#include "util.h"
#include "strxcpyx.h"
#include "fileio.h"
#include "strv.h"
#include "unit-name.h"
#include "special.h"
#include "hashmap.h"

#include "control-response-util.h"
*/

int main(int argc, char *argv[]) {
        puts("systemd-analyze is a NOP at present. "
             "It is to be reworked within the new IPC framework of uselessd.");
}
