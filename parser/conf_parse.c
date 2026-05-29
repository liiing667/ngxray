/*
 * AST builder and JSON emitter for the standalone nginx config parser.
 *
 * Replaces ngx_conf_handler() with conf_handler(), which records every
 * directive into a tree instead of dispatching to nginx modules.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <sys/stat.h>
#include "conf_parse.h"


conf_tree_t *
conf_tree_create(ngx_pool_t *pool)
{
    conf_tree_t  *tree;
    conf_node_t  *root;

    tree = ngx_pcalloc(pool, sizeof(conf_tree_t));
    if (tree == NULL) {
        return NULL;
    }

    root = ngx_pcalloc(pool, sizeof(conf_node_t));
    if (root == NULL) {
        return NULL;
    }

    tree->pool = pool;
    tree->root = root;
    tree->current = root;

    return tree;
}


static conf_node_t *
conf_node_create(conf_tree_t *tree, ngx_conf_t *cf)
{
    conf_node_t  *node;
    ngx_str_t    *args, *src, *dst;
    ngx_uint_t    i;

    node = ngx_pcalloc(tree->pool, sizeof(conf_node_t));
    if (node == NULL) {
        return NULL;
    }

    args = cf->args->elts;

    node->directive.len = args[0].len;
    node->directive.data = ngx_pstrdup(tree->pool, &args[0]);

    if (cf->args->nelts > 1) {
        if (ngx_array_init(&node->args, tree->pool,
                           cf->args->nelts - 1, sizeof(ngx_str_t))
            != NGX_OK)
        {
            return NULL;
        }

        for (i = 1; i < cf->args->nelts; i++) {
            src = &args[i];
            dst = ngx_array_push(&node->args);
            if (dst == NULL) {
                return NULL;
            }
            dst->len = src->len;
            dst->data = ngx_pstrdup(tree->pool, src);
        }
    }

    if (cf->conf_file) {
        node->line = cf->conf_file->line;
        node->file.len = cf->conf_file->file.name.len;
        node->file.data = cf->conf_file->file.name.data;
    }

    return node;
}


static void
conf_node_append(conf_node_t *parent, conf_node_t *child)
{
    conf_node_t  **pp;

    pp = &parent->children;
    while (*pp) {
        pp = &(*pp)->next;
    }
    *pp = child;
}


ngx_int_t
conf_handler(ngx_conf_t *cf, ngx_int_t last)
{
    conf_tree_t  *tree;
    conf_node_t  *node;
    ngx_str_t    *name;
    char         *rv;

    tree = cf->handler_conf;
    name = cf->args->elts;

    if (name[0].len == 7
        && ngx_strncmp(name[0].data, "include", 7) == 0
        && cf->args->nelts == 2)
    {
        node = conf_node_create(tree, cf);
        if (node == NULL) {
            return NGX_ERROR;
        }
        conf_node_append(tree->current, node);

        /* Resolve the include path, then skip if the target is missing.
         * This avoids noisy "open() failed" errors when scanning configs
         * outside their original filesystem (e.g. corpus collection). */
        {
            ngx_str_t  inc_file;
            ngx_str_t *args = cf->args->elts;

            inc_file = args[1];

            if (ngx_conf_full_name(cf->cycle, &inc_file, 1) == NGX_OK) {
                if (strpbrk((char *) inc_file.data, "*?[") == NULL) {
                    struct stat  sb;
                    if (stat((char *) inc_file.data, &sb) != 0) {
                        return NGX_OK;
                    }
                }
            }
        }

        rv = ngx_conf_include(cf, NULL, NULL);
        if (rv != NGX_CONF_OK) {
            return NGX_OK;
        }
        return NGX_OK;
    }

    node = conf_node_create(tree, cf);
    if (node == NULL) {
        return NGX_ERROR;
    }

    conf_node_append(tree->current, node);

    if (last == NGX_CONF_BLOCK_START) {
        conf_node_t  *prev_parent;

        prev_parent = tree->current;
        tree->current = node;
        tree->depth++;

        rv = ngx_conf_parse(cf, NULL);

        tree->current = prev_parent;
        tree->depth--;

        if (rv != NGX_CONF_OK) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
conf_parse_file(conf_tree_t *tree, ngx_log_t *log, const char *filename)
{
    ngx_conf_t   cf;
    ngx_str_t    file;
    ngx_cycle_t  cycle;
    ngx_array_t  args;
    char        *rv;

    ngx_memzero(&cycle, sizeof(ngx_cycle_t));
    ngx_memzero(&cf, sizeof(ngx_conf_t));

    cycle.pool = tree->pool;
    cycle.log = log;

    {
        u_char  *p, *dir;
        size_t   len;

        len = ngx_strlen(filename);
        p = (u_char *)filename + len;
        while (p > (u_char *)filename && *(p - 1) != '/') {
            p--;
        }
        if (p > (u_char *)filename) {
            dir = ngx_pnalloc(tree->pool, p - (u_char *)filename + 1);
            if (dir == NULL) {
                return NGX_ERROR;
            }
            ngx_cpystrn(dir, (u_char *)filename,
                        p - (u_char *)filename + 1);
            cycle.conf_prefix.data = dir;
            cycle.conf_prefix.len = p - (u_char *)filename;
        } else {
            ngx_str_set(&cycle.conf_prefix, "./");
        }
        cycle.prefix = cycle.conf_prefix;
    }

    if (ngx_list_init(&cycle.open_files, tree->pool, 4,
                      sizeof(ngx_open_file_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&cycle.config_dump_rbtree,
                    &cycle.config_dump_sentinel,
                    ngx_str_rbtree_insert_value);
    if (ngx_array_init(&cycle.config_dump, tree->pool, 1,
                       sizeof(ngx_conf_dump_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    {
        static ngx_module_t  *empty_modules[] = { NULL };
        cycle.modules = empty_modules;
    }

    if (ngx_array_init(&args, tree->pool, 10, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    cf.cycle = &cycle;
    cf.pool = tree->pool;
    cf.temp_pool = tree->pool;
    cf.log = log;
    cf.args = &args;
    cf.module_type = NGX_CONF_MODULE;
    cf.cmd_type = NGX_ANY_CONF;
    cf.handler = NULL;
    cf.handler_conf = tree;

    file.data = (u_char *)filename;
    file.len = ngx_strlen(filename);

    rv = ngx_conf_parse(&cf, &file);

    return (rv == NGX_CONF_OK) ? NGX_OK : NGX_ERROR;
}


/* ── JSON output ────────────────────────────────────────────────────── */

static void
json_escape(FILE *out, u_char *data, size_t len)
{
    size_t  i;

    fputc('"', out);
    for (i = 0; i < len; i++) {
        switch (data[i]) {
        case '"':   fputs("\\\"", out); break;
        case '\\':  fputs("\\\\", out); break;
        case '\n':  fputs("\\n", out);  break;
        case '\r':  fputs("\\r", out);  break;
        case '\t':  fputs("\\t", out);  break;
        default:
            if (data[i] < 0x20) {
                fprintf(out, "\\u%04x", data[i]);
            } else {
                fputc(data[i], out);
            }
        }
    }
    fputc('"', out);
}


static void
node_to_json(conf_node_t *node, FILE *out, int indent)
{
    conf_node_t  *child;
    ngx_str_t    *arg;
    ngx_uint_t    i;
    int           ind;

    for (ind = 0; ind < indent; ind++) fputs("  ", out);

    fputs("{\"directive\":", out);
    json_escape(out, node->directive.data, node->directive.len);
    fprintf(out, ",\"line\":%lu,\"args\":[", (unsigned long)node->line);

    if (node->args.nelts > 0) {
        arg = node->args.elts;
        for (i = 0; i < node->args.nelts; i++) {
            if (i > 0) fputc(',', out);
            json_escape(out, arg[i].data, arg[i].len);
        }
    }
    fputs("]", out);

    if (node->children) {
        fputs(",\"block\":[\n", out);
        for (child = node->children; child; child = child->next) {
            node_to_json(child, out, indent + 1);
            fputs(child->next ? ",\n" : "\n", out);
        }
        for (ind = 0; ind < indent; ind++) fputs("  ", out);
        fputs("]", out);
    }

    fputs("}", out);
}


void
conf_tree_to_json(conf_tree_t *tree, FILE *out)
{
    conf_node_t  *node;

    fputs("[\n", out);
    for (node = tree->root->children; node; node = node->next) {
        node_to_json(node, out, 1);
        fputs(node->next ? ",\n" : "\n", out);
    }
    fputs("]\n", out);
}
