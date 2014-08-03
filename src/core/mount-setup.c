/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/mount.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>
#include <unistd.h>
#include <ftw.h>

#include "mount-setup.h"
#include "dev-setup.h"
#include "log.h"
#include "macro.h"
#include "util.h"
#include "label.h"
#include "set.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "missing.h"
#include "efivars.h"

#ifndef TTY_GID
#define TTY_GID 5
#endif

typedef enum MountMode {
        MNT_NONE  =        0,
        MNT_FATAL =        1 <<  0,
        MNT_IN_CONTAINER = 1 <<  1,
} MountMode;

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;
        bool (*condition_fn)(void);
        MountMode mode;
} MountPoint;

/* The first three entries we might need before SELinux is up. The
 * fourth (securityfs) is needed by IMA to load a custom policy. The
 * other ones we can delay until SELinux and IMA are loaded. */
#define N_EARLY_MOUNT 5

static const MountPoint mount_table[] = {
        { "devtmpfs",   "/dev",                      "devtmpfs",   "mode=755", MNT_NOSUID,
          NULL,       MNT_FATAL|MNT_IN_CONTAINER },
        { "tmpfs",      "/dev/shm",                  "tmpfs",      "mode=1777", MNT_NOSUID,
          NULL,       MNT_FATAL|MNT_IN_CONTAINER },
        { "devpts",     "/dev/pts",                  "devpts",     "mode=620,gid=" STRINGIFY(TTY_GID), MNT_NOSUID|MNT_NOEXEC,
          NULL,       MNT_IN_CONTAINER },
        { "tmpfs",      "/run",                      "tmpfs",      "mode=755", MNT_NOSUID,
          NULL,       MNT_FATAL|MNT_IN_CONTAINER },
};

/* These are API file systems that might be mounted by other software,
 * we just list them here so that we know that we should ignore them */

static const char ignore_paths[] =
        /* SELinux file systems */
        "/sys/fs/selinux\0"
        "/selinux\0"
        /* Legacy cgroup mount points */
        "/dev/cgroup\0"
        "/cgroup\0"
        /* Legacy kernel file system */
        "/proc/bus/usb\0"
        /* Container bind mounts */
        "/proc/sys\0"
        "/dev/console\0"
        "/proc/kmsg\0";

bool mount_point_is_api(const char *path) {
        unsigned i;

        /* Checks if this mount point is considered "API", and hence
         * should be ignored */

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if (path_equal(path, mount_table[i].where))
                        return true;

        return path_startswith(path, "/sys/fs/cgroup/");
}

bool mount_point_ignore(const char *path) {
        const char *i;

        NULSTR_FOREACH(i, ignore_paths)
                if (path_equal(path, i))
                        return true;

        return false;
}

static int mount_one(const MountPoint *p, bool relabel) {
        int r;

        assert(p);

        if (p->condition_fn && !p->condition_fn())
                return 0;

        /* Relabel first, just in case */
        if (relabel)
                label_fix(p->where, true, true);

        r = path_is_mount_point(p->where, true);
        if (r < 0)
                return r;

        if (r > 0)
                return 0;

        /* Skip securityfs in a container */
        if (!(p->mode & MNT_IN_CONTAINER))
                return 0;

        /* The access mode here doesn't really matter too much, since
         * the mounted file system will take precedence anyway. */
        mkdir_p_label(p->where, 0755);

        log_debug("Mounting %s to %s of type %s with options %s.",
                  p->what,
                  p->where,
                  p->type,
                  strna(p->options));

        if (mount(p->what,
                  p->where,
                  p->type,
                  p->flags) < 0) {
                log_full((p->mode & MNT_FATAL) ? LOG_ERR : LOG_DEBUG, "Failed to mount %s: %s", p->where, strerror(errno));
                return (p->mode & MNT_FATAL) ? -errno : 0;
        }

        /* Relabel again, since we now mounted something fresh here */
        if (relabel)
                label_fix(p->where, false, false);

        return 1;
}

int mount_setup_early(void) {
        unsigned i;
        int r = 0;

        //assert_cc(N_EARLY_MOUNT <= ELEMENTSOF(mount_table));

        /* Do a minimal mount of /proc and friends to enable the most
         * basic stuff, such as SELinux */
        for (i = 0; i < N_EARLY_MOUNT; i ++)  {
                int j;

                j = mount_one(mount_table + i, false);
                if (r == 0)
                        r = j;
        }

        return r;
}

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        /* No need to label /dev twice in a row... */
        if (_unlikely_(ftwbuf->level == 0))
                return FTW_CONTINUE;

        label_fix(fpath, false, false);

        return FTW_CONTINUE;
};

int mount_setup(bool loaded_policy) {
        int r;
        unsigned i;

        for (i = 0; i < ELEMENTSOF(mount_table); i ++) {
                r = mount_one(mount_table + i, true);

                if (r < 0)
                        return r;
        }

        /* Nodes in devtmpfs and /run need to be manually updated for
         * the appropriate labels, after mounting. The other virtual
         * API file systems like /sys and /proc do not need that, they
         * use the same label for all their files. */
        if (loaded_policy) {
                usec_t before_relabel, after_relabel;
                char timespan[FORMAT_TIMESPAN_MAX];

                before_relabel = now(CLOCK_MONOTONIC);

                nftw("/dev", nftw_cb, 64, FTW_MOUNT|FTW_PHYS);
                nftw("/run", nftw_cb, 64, FTW_MOUNT|FTW_PHYS);

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabelled /dev and /run in %s.",
                         format_timespan(timespan, sizeof(timespan), after_relabel - before_relabel, 0));
        }

        /* Create a few default symlinks, which are normally created
         * by udevd, but some scripts might need them before we start
         * udevd. */
        dev_setup(NULL);

        /* Create a few directories we always want around, Note that
         * sd_booted() checks for /run/systemd/system, so this mkdir
         * really needs to stay for good, otherwise software that
         * copied sd-daemon.c into their sources will misdetect
         * systemd. */
        mkdir_label("/run/systemd", 0755);
        mkdir_label("/run/systemd/system", 0755);
        mkdir_label("/run/systemd/inaccessible", 0000);

        return 0;
}
