uselessd System and Service Manager [original description do not steal]
     -----------------------------------------

    WEB SITE + DETAILS:
        http://uselessd.darknedgy.net [read it]

    IRC:
        #uselessd on irc.darknedgy.net

    AUTHOR:
        Lennart Poettering
        Kay Sievers
        The Initfinder General
        ...and many others

    LICENSE:
        LGPLv2.1+ for all code
        - except sd-daemon.[ch] which is MIT
        - except src/shared/MurmurHash3.c which is Public Domain

    REQUIREMENTS:
        Linux kernel >= 3.4
       (might be 3.0 or less if using --disable-initd, but this has
       not been tested)
           CONFIG_DEVTMPFS
           CONFIG_CGROUPS (it's OK to disable all controllers)
           CONFIG_INOTIFY_USER
           CONFIG_SIGNALFD
           CONFIG_TIMERFD
           CONFIG_EPOLL
           CONFIG_NET
           CONFIG_SYSFS
           CONFIG_PROC_FS

        Mount and bind mount handling might require it:
          CONFIG_FHANDLE

        Support for some SCSI devices serial number retrieval, to
        create additional symlinks in /dev/disk/ and /dev/tape:
          CONFIG_BLK_DEV_BSG

        Required for PrivateNetwork in service units:
          CONFIG_NET_NS

        Optional but strongly recommended:
          CONFIG_IPV6
          CONFIG_AUTOFS4_FS
          CONFIG_TMPFS_POSIX_ACL
          CONFIG_TMPFS_XATTR
          CONFIG_SECCOMP

        Required for CPUShares in resource control unit settings:
         CONFIG_CGROUP_SCHED
         CONFIG_FAIR_GROUP_SCHED

        For UEFI systems:
          CONFIG_EFI_VARS
          CONFIG_EFI_PARTITION

        Note that kernel auditing is broken when used with systemd's
        container code. When using systemd/uselessd in conjunction with
        containers please make sure to either turn off auditing at
        runtime using the kernel command line option "audit=0", or
        turn it off at kernel compile time using:
          CONFIG_AUDIT=n

        dbus >= 1.4.0
        libcap
        libblkid >= 2.20 (from util-linux) (optional)
        libkmod >= 14 (optional)
        PAM >= 1.1.2 (optional)
        libaudit (optional)
        libacl (optional)
        libattr (optional)
        libselinux (optional)
        libpython (optional)
        make, gcc, and similar tools

        During runtime you need the following additional dependencies:

        util-linux >= v2.19 (requires fsck -l, agetty -s, losetup)
        dmsetup
        sulogin (from util-linux >= 2.22 or sysvinit-tools, optional but recommended)
        dracut (optional)
        PolicyKit (optional)

        When building from git you need the following additional dependencies:

        docbook-xsl
        xsltproc
        automake
        autoconf
        libtool
        intltool
        gperf
        gtkdocize (optional)
        python (optional)
        sphinx (optional)
        python-lxml (entirely optional)

        To build HTML documentation for python-systemd using sphinx,
        please first install systemd (using 'make install'), and then
        invoke sphinx-build with 'make sphinx-<target>', with <target>
        being 'html' or 'latexpdf'. If using DESTDIR for installation,
        pass the same DESTDIR to 'make sphinx-html' invocation.


    WARNINGS:
        systemd/uselessd will warn you during boot if /etc/mtab is not a
        symlink to /proc/mounts. Please ensure that /etc/mtab is a
        proper symlink.

        systemd/uselessd will warn you during boot if /usr is on a different
        file system than /. While in systemd itself very little will
        break if /usr is on a separate partition many of its
        dependencies very likely will break sooner or later in one
        form or another. For example udev rules tend to refer to
        binaries in /usr, binaries that link to libraries in /usr or
        binaries that refer to data files in /usr. Since these
        breakages are not always directly visible systemd will warn
        about this, since this kind of file system setup is not really
        supported anymore by the basic set of Linux OS components.

        For more information on this issue consult
        http://freedesktop.org/wiki/Software/systemd/separate-usr-is-broken

        To run uselessd under valgrind, compile with VALGRIND defined
        (e.g. ./configure CPPFLAGS='... -DVALGRIND=1'). Otherwise,
        false positives will be triggered by code which violates
        some rules but is actually safe.
