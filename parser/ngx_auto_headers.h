#ifndef NGX_HAVE_UNISTD_H
#define NGX_HAVE_UNISTD_H  1
#endif

#ifndef NGX_HAVE_INTTYPES_H
#define NGX_HAVE_INTTYPES_H  1
#endif

#ifndef NGX_HAVE_LIMITS_H
#define NGX_HAVE_LIMITS_H  1
#endif

#ifndef NGX_HAVE_SYS_FILIO_H
#define NGX_HAVE_SYS_FILIO_H  1
#endif

#ifndef NGX_HAVE_SYS_PARAM_H
#define NGX_HAVE_SYS_PARAM_H  1
#endif

#ifndef NGX_HAVE_SYS_MOUNT_H
#define NGX_HAVE_SYS_MOUNT_H  1
#endif

#ifndef NGX_HAVE_SYS_STATVFS_H
#define NGX_HAVE_SYS_STATVFS_H  1
#endif

#if defined(__APPLE__)
#ifndef NGX_DARWIN
#define NGX_DARWIN  1
#endif
#elif defined(__linux__)
#ifndef NGX_LINUX
#define NGX_LINUX  1
#endif
#elif defined(__FreeBSD__)
#ifndef NGX_FREEBSD
#define NGX_FREEBSD  1
#endif
#else
#endif
