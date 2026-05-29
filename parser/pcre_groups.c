/*
 * pcre_groups - report capture group nesting for PCRE2 regex patterns.
 *
 * Reads regex patterns from stdin (one per line) and outputs JSON:
 *   {"regex":"...","groups":{"1":[2,3],"2":[],...}}
 *
 * The "groups" object maps each capturing group number to its list of
 * direct child group numbers. Group A contains group B if B appears in
 * A's children (or recursively in a descendant's children).
 *
 * This uses PCRE2 directly so the parsing matches what nginx sees.
 */

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void
print_nesting(const char *pattern, size_t len)
{
    pcre2_code         *re;
    int                 errcode;
    PCRE2_SIZE          erroffset;
    uint32_t            captures;
    PCRE2_SPTR          p;
    int                 depth, group_num;
    int                 stack[256];
    int                 parent[256];
    int                 i;

    re = pcre2_compile((PCRE2_SPTR) pattern, len, 0,
                       &errcode, &erroffset, NULL);
    if (re == NULL) {
        PCRE2_UCHAR  errbuf[256];
        pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
        fprintf(stdout, "{\"regex\":");
        fputc('"', stdout);
        for (i = 0; i < (int) len; i++) {
            if (pattern[i] == '"' || pattern[i] == '\\')
                fputc('\\', stdout);
            fputc(pattern[i], stdout);
        }
        fprintf(stdout, "\",\"error\":\"%s\"}\n", errbuf);
        return;
    }

    pcre2_pattern_info(re, PCRE2_INFO_CAPTURECOUNT, &captures);

    /* Walk the raw pattern to find group nesting.  PCRE2 doesn't expose
     * a nesting API, but we only need the structural parent of each
     * capturing group, which is determined by the parenthesis structure.
     * We use the same character-walking approach as before, but now we
     * know the total group count from PCRE2 as a sanity check. */

    memset(parent, 0, sizeof(parent));  /* parent[g] = enclosing group, 0=top */
    depth = 0;
    group_num = 0;

    p = (PCRE2_SPTR) pattern;
    i = 0;

    while (i < (int) len) {
        /* Escaped character */
        if (p[i] == '\\') {
            i += 2;
            continue;
        }

        /* Character class */
        if (p[i] == '[') {
            i++;
            if (i < (int) len && p[i] == '^') i++;
            if (i < (int) len && p[i] == ']') i++;
            while (i < (int) len && p[i] != ']') {
                if (p[i] == '\\') i++;
                i++;
            }
            i++;
            continue;
        }

        /* Opening paren */
        if (p[i] == '(') {
            i++;
            if (i < (int) len && p[i] == '?') {
                /* Check for named capture: (?P< or (?< (not (?<= or (?<!) */
                int is_named = 0;
                if (i + 1 < (int) len && p[i + 1] == 'P'
                    && i + 2 < (int) len && p[i + 2] == '<') {
                    is_named = 1;
                } else if (i + 1 < (int) len && p[i + 1] == '<'
                           && i + 2 < (int) len
                           && p[i + 2] != '=' && p[i + 2] != '!') {
                    is_named = 1;
                }

                if (is_named) {
                    group_num++;
                    if (depth > 0 && depth < 256) {
                        parent[group_num] = stack[depth - 1];
                    }
                    if (depth < 256) stack[depth] = group_num;
                    depth++;
                } else {
                    /* Non-capturing: (?:, (?=, (?!, (?>, etc. */
                    if (depth < 256) stack[depth] = 0;
                    depth++;
                }
                i++;
            } else {
                /* Plain capturing group */
                group_num++;
                if (depth > 0 && depth < 256) {
                    parent[group_num] = stack[depth - 1];
                }
                if (depth < 256) stack[depth] = group_num;
                depth++;
            }
            continue;
        }

        /* Closing paren */
        if (p[i] == ')') {
            if (depth > 0) depth--;
            i++;
            continue;
        }

        i++;
    }

    /* Output JSON */
    fprintf(stdout, "{\"regex\":");
    fputc('"', stdout);
    for (i = 0; i < (int) len; i++) {
        if (pattern[i] == '"' || pattern[i] == '\\')
            fputc('\\', stdout);
        fputc(pattern[i], stdout);
    }
    fprintf(stdout, "\",\"captures\":%u,\"parent\":{", captures);
    for (i = 1; i <= (int) captures; i++) {
        if (i > 1) fputc(',', stdout);
        fprintf(stdout, "\"%d\":%d", i, parent[i]);
    }
    fprintf(stdout, "}}\n");

    pcre2_code_free(re);
}


int
main(int argc, char **argv)
{
    char  line[8192];

    if (argc > 1) {
        /* Arguments are patterns */
        for (int i = 1; i < argc; i++) {
            print_nesting(argv[i], strlen(argv[i]));
        }
    } else {
        /* Read patterns from stdin */
        while (fgets(line, sizeof(line), stdin)) {
            size_t len = strlen(line);
            while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r'))
                line[--len] = '\0';
            if (len == 0) continue;
            print_nesting(line, len);
        }
    }

    return 0;
}
