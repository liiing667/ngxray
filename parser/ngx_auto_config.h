/*
 * Minimal ngx_auto_config.h for standalone config parser.
 * Replaces the configure-generated version.
 */

#ifndef NGX_HAVE_GCC_ATOMIC
#define NGX_HAVE_GCC_ATOMIC  1
#endif

#ifndef NGX_HAVE_C99_VARIADIC_MACROS
#define NGX_HAVE_C99_VARIADIC_MACROS  1
#endif

#ifndef NGX_HAVE_GCC_VARIADIC_MACROS
#define NGX_HAVE_GCC_VARIADIC_MACROS  1
#endif

#ifndef NGX_HAVE_GCC_BSWAP64
#define NGX_HAVE_GCC_BSWAP64  1
#endif

#ifndef NGX_CPU_CACHE_LINE
#define NGX_CPU_CACHE_LINE  64
#endif

#ifndef NGX_ALIGNMENT
#define NGX_ALIGNMENT  16
#endif

#ifndef NGX_PTR_SIZE
#define NGX_PTR_SIZE  8
#endif

#ifndef NGX_HAVE_LITTLE_ENDIAN
#define NGX_HAVE_LITTLE_ENDIAN  1
#endif

#ifndef NGX_MAX_SIZE_T_VALUE
#define NGX_MAX_SIZE_T_VALUE  9223372036854775807LL
#endif

#ifndef NGX_SIZE_T_LEN
#define NGX_SIZE_T_LEN  (sizeof("-9223372036854775808") - 1)
#endif

#ifndef NGX_MAX_OFF_T_VALUE
#define NGX_MAX_OFF_T_VALUE  9223372036854775807LL
#endif

#ifndef NGX_OFF_T_LEN
#define NGX_OFF_T_LEN  (sizeof("-9223372036854775808") - 1)
#endif

#ifndef NGX_TIME_T_SIZE
#define NGX_TIME_T_SIZE  8
#endif

#ifndef NGX_TIME_T_LEN
#define NGX_TIME_T_LEN  (sizeof("-9223372036854775808") - 1)
#endif

#ifndef NGX_MAX_TIME_T_VALUE
#define NGX_MAX_TIME_T_VALUE  9223372036854775807LL
#endif

#ifndef NGX_SIG_ATOMIC_T_SIZE
#define NGX_SIG_ATOMIC_T_SIZE  4
#endif

#ifndef NGX_HAVE_PREAD
#define NGX_HAVE_PREAD  1
#endif

#ifndef NGX_HAVE_LOCALTIME_R
#define NGX_HAVE_LOCALTIME_R  1
#endif

#ifndef NGX_HAVE_POSIX_MEMALIGN
#define NGX_HAVE_POSIX_MEMALIGN  1
#endif

#ifndef NGX_HAVE_MAP_ANON
#define NGX_HAVE_MAP_ANON  1
#endif

#ifndef NGX_HAVE_DLOPEN
#define NGX_HAVE_DLOPEN  1
#endif

#ifndef NGX_HAVE_INET6
#define NGX_HAVE_INET6  1
#endif

#ifndef NGX_HAVE_UNIX_DOMAIN
#define NGX_HAVE_UNIX_DOMAIN  1
#endif

#ifndef NGX_HAVE_D_NAMLEN
#define NGX_HAVE_D_NAMLEN  1
#endif

#ifndef NGX_HAVE_D_TYPE
#define NGX_HAVE_D_TYPE  1
#endif

#ifndef NGX_HAVE_FIONBIO
#define NGX_HAVE_FIONBIO  1
#endif

#ifndef NGX_HAVE_OPENAT
#define NGX_HAVE_OPENAT  1
#endif

#ifndef NGX_HAVE_GMTOFF
#define NGX_HAVE_GMTOFF  1
#endif

#ifndef NGX_HAVE_STATFS
#define NGX_HAVE_STATFS  1
#endif

#ifndef NGX_HAVE_STATVFS
#define NGX_HAVE_STATVFS  1
#endif

#ifndef NGX_SYS_NERR
#define NGX_SYS_NERR  108
#endif

#ifndef NGX_SUPPRESS_WARN
#define NGX_SUPPRESS_WARN  1
#endif

#ifndef NGX_PREFIX
#define NGX_PREFIX  ""
#endif

#ifndef NGX_CONF_PREFIX
#define NGX_CONF_PREFIX  ""
#endif

#ifndef NGX_ERROR_LOG_PATH
#define NGX_ERROR_LOG_PATH  ""
#endif

#ifndef NGX_CONF_PATH
#define NGX_CONF_PATH  ""
#endif

#ifndef NGX_PID_PATH
#define NGX_PID_PATH  ""
#endif

#ifndef NGX_LOCK_PATH
#define NGX_LOCK_PATH  ""
#endif

#ifndef NGX_HTTP_LOG_PATH
#define NGX_HTTP_LOG_PATH  ""
#endif

#ifndef NGX_HAVE_SENDFILE
#define NGX_HAVE_SENDFILE  1
#endif

#ifndef NGX_HAVE_F_NOCACHE
#define NGX_HAVE_F_NOCACHE  1
#endif
