/*
 * nginx_conf_parse — standalone nginx config parser.
 * Outputs a JSON AST to stdout using the real nginx tokenizer.
 *
 * Usage: nginx_conf_parse <file>          (single file, JSON array)
 *        nginx_conf_parse <f1> <f2> ...   (multiple files, JSONL)
 *        nginx_conf_parse -               (filenames from stdin, JSONL)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include "conf_parse.h"

volatile ngx_cycle_t  *ngx_cycle;
ngx_uint_t             ngx_dump_config = 0;
ngx_uint_t             ngx_pagesize;
ngx_uint_t             ngx_pagesize_shift;
ngx_uint_t             ngx_cacheline_size;
ngx_uint_t             ngx_max_module;
volatile ngx_time_t   *ngx_cached_time;
static ngx_time_t      fake_time;


static ngx_log_t *
create_log(void)
{
    static ngx_log_t       log;
    static ngx_open_file_t log_file;

    ngx_memzero(&log, sizeof(ngx_log_t));
    ngx_memzero(&log_file, sizeof(ngx_open_file_t));

    log_file.fd = STDERR_FILENO;
    ngx_str_set(&log_file.name, "stderr");

    log.file = &log_file;
    log.log_level = NGX_LOG_WARN;

    return &log;
}


static int
parse_one(const char *filename, ngx_log_t *log, int jsonl)
{
    ngx_pool_t   *pool;
    conf_tree_t  *tree;

    pool = ngx_create_pool(16384, log);
    if (pool == NULL) {
        return 1;
    }

    tree = conf_tree_create(pool);
    if (tree == NULL) {
        ngx_destroy_pool(pool);
        return 1;
    }

    if (jsonl) {
        fprintf(stdout, "{\"file\":");
        fputc('"', stdout);
        for (const char *p = filename; *p; p++) {
            if (*p == '"' || *p == '\\') fputc('\\', stdout);
            fputc(*p, stdout);
        }
        fputc('"', stdout);
    }

    if (conf_parse_file(tree, log, filename) != NGX_OK) {
        if (jsonl) {
            fputs(",\"error\":true,\"config\":[]}\n", stdout);
        }
        ngx_destroy_pool(pool);
        return 1;
    }

    if (jsonl) fputs(",\"config\":", stdout);
    conf_tree_to_json(tree, stdout);
    if (jsonl) fputs("}\n", stdout);

    ngx_destroy_pool(pool);
    return 0;
}


int
main(int argc, char **argv)
{
    ngx_log_t  *log;
    int         rc = 0;

    ngx_pagesize = getpagesize();
    {
        ngx_uint_t ps = ngx_pagesize;
        ngx_pagesize_shift = 0;
        while (ps >>= 1) ngx_pagesize_shift++;
    }
    ngx_cacheline_size = NGX_CPU_CACHE_LINE;
    ngx_memzero(&fake_time, sizeof(ngx_time_t));
    ngx_cached_time = &fake_time;
    ngx_strerror_init();

    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <config_file> [config_file ...]\n"
            "       %s -   (read filenames from stdin, JSONL output)\n",
            argv[0], argv[0]);
        return 1;
    }

    {
        static ngx_cycle_t  stub_cycle;
        ngx_pool_t          *gpool;

        gpool = ngx_create_pool(4096, NULL);
        if (gpool == NULL) return 1;

        ngx_memzero(&stub_cycle, sizeof(ngx_cycle_t));
        stub_cycle.pool = gpool;
        ngx_str_set(&stub_cycle.conf_prefix, "");
        ngx_str_set(&stub_cycle.prefix, "");

        if (ngx_list_init(&stub_cycle.open_files, gpool, 4,
                          sizeof(ngx_open_file_t)) != NGX_OK)
            return 1;

        ngx_cycle = &stub_cycle;
    }

    log = create_log();
    ((ngx_cycle_t *)ngx_cycle)->log = log;

    if (argc == 2 && strcmp(argv[1], "-") == 0) {
        char path[4096];
        while (fgets(path, sizeof(path), stdin)) {
            size_t len = strlen(path);
            while (len > 0 && (path[len-1] == '\n' || path[len-1] == '\r'))
                path[--len] = '\0';
            if (len == 0) continue;
            parse_one(path, log, 1);
        }
        return 0;
    }

    for (int i = 1; i < argc; i++) {
        if (parse_one(argv[i], log, argc > 2) != 0) rc = 1;
    }

    return rc;
}
