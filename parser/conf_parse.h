#ifndef _CONF_PARSE_H_INCLUDED_
#define _CONF_PARSE_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

typedef struct conf_node_s  conf_node_t;

struct conf_node_s {
    ngx_str_t       directive;
    ngx_array_t     args;
    ngx_uint_t      line;
    ngx_str_t       file;
    conf_node_t    *children;
    conf_node_t    *next;
};

typedef struct {
    ngx_pool_t     *pool;
    conf_node_t    *root;
    conf_node_t    *current;
    ngx_uint_t      depth;
    ngx_str_t       file;
} conf_tree_t;

conf_tree_t *conf_tree_create(ngx_pool_t *pool);
ngx_int_t    conf_parse_file(conf_tree_t *tree, ngx_log_t *log,
                             const char *filename);
void         conf_tree_to_json(conf_tree_t *tree, FILE *out);

#endif
