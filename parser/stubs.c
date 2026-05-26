/*
 * Stubs for symbols referenced by nginx source files we compile
 * but never called during config parsing.
 */

#include <ngx_config.h>
#include <ngx_core.h>

ngx_pid_t           ngx_pid = 0;
volatile ngx_str_t  ngx_cached_err_log_time = { 0, (u_char *) "" };

ssize_t ngx_parse_size(ngx_str_t *line)  { return -1; }
off_t   ngx_parse_offset(ngx_str_t *line) { return -1; }

ngx_int_t
ngx_parse_time(ngx_str_t *line, ngx_uint_t is_sec) { return -1; }

char *
ngx_syslog_process_conf(ngx_conf_t *cf, ngx_syslog_peer_t *peer)
{
    return NGX_CONF_ERROR;
}

void
ngx_syslog_writer(ngx_log_t *log, ngx_uint_t level, u_char *buf, size_t len) {}
