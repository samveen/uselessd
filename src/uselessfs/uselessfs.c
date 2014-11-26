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

#define FUSE_USE_VERSION 26

#include <fuse/fuse.h>

#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>

#include "log.h"

/*TODO: fullpath*/
int useless_getattr(const char *path, struct stat *statbuf);
int useless_open(const char *path, struct fuse_file_info *fi);
int useless_creat(const char *path, mode_t mode, struct fuse_file_info *fi);
int useless_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int useless_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                struct fuse_file_info *fi);
int useless_releasedir(const char *path, struct fuse_file_info *fi);
int useless_unlink(const char *path);

int useless_getattr(const char *path, struct stat *statbuf) {
        int ret = 0;
        char fpath[PATH_MAX];

        ret = lstat(fpath, statbuf);
        if (ret != 0)
                log_error("uselessfs lstat() failed: %s", strerror(-ret));

        return ret;
}

int useless_open(const char *path, struct fuse_file_info *fi) {
        int ret = 0;
        int fd;
        char fpath[PATH_MAX];

        fd = open(fpath, fi->flags);
        if (fd < 0)
                ret = log_error("uselessfs open() failed: %s", strerror(-ret));

        fi->fh = fd;

        return ret;
}

int useless_creat(const char *path, mode_t mode, struct fuse_file_info *fi) {
        int ret = 0;
        char fpath[PATH_MAX];
        int fd;

        fd = creat(fpath, mode);
        if (fd < 0)
                log_error("uselessfs creat() failed: %s", strerror(-ret));

        fi->fh = fd;

        return ret;
}

int useless_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
        int ret = 0;

        ret = pread(fi->fh, buf, size, offset);
        if (ret < 0)
                log_error("uselessfs pread() failed: %s", strerror(-ret));

        return ret;
}

int useless_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                struct fuse_file_info *fi) {

        int ret = 0;
        DIR *dp;
        struct dirent *de;

        dp = (DIR *) (uintptr_t) fi->fh;

        de = readdir(dp);
        if (de == 0) {
                ret = log_error("uselessfs readdir() failed: %s", strerror(-ret));
                return ret;
        }

        /* Loop and copy directory into buffer. */
        do {
                if (filler(buf, de->d_name, NULL, 0) != 0) {
                        log_error("uselessfs readdir() filler: buffer full: %s", strerror(-ret));
                        return -ENOMEM;
        }
        } while ((de = readdir(dp)) != NULL);

        return ret;
}

int useless_releasedir(const char *path, struct fuse_file_info *fi) {
        int ret = 0;

        closedir((DIR *) (uintptr_t) fi->fh);

        return ret;
}

int useless_unlink(const char *path) {
        int ret = 0;
        char fpath[PATH_MAX];

        ret = unlink(fpath);
        if (ret < 0)
                log_error("uselessfs unlink() failed: %s", strerror(-ret));

        return ret;
}

struct fuse_operations fsops = {
	.read = useless_read,
        .readdir = useless_readdir,
        .releasedir = useless_releasedir,
	.open = useless_open,
        .create = useless_creat,
        .unlink = useless_unlink,
	.getattr = useless_getattr
};

int main(int argc, char *argv[]) {

        return fuse_main(argc, argv, &fsops, NULL);
}
