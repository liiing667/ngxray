NGX_SRC  = nginx/src
CC      ?= cc
CFLAGS  ?= -O2
CFLAGS  += -Wall -Wno-unused-function -Wno-deprecated-declarations

INCLUDES = -Iparser \
           -I$(NGX_SRC)/core \
           -I$(NGX_SRC)/os/unix \
           -I$(NGX_SRC)/event \
           -I$(NGX_SRC)/http \
           -I$(NGX_SRC)/http/modules

NGX_SRCS = $(NGX_SRC)/core/ngx_palloc.c \
           $(NGX_SRC)/core/ngx_array.c \
           $(NGX_SRC)/core/ngx_list.c \
           $(NGX_SRC)/core/ngx_buf.c \
           $(NGX_SRC)/core/ngx_string.c \
           $(NGX_SRC)/core/ngx_log.c \
           $(NGX_SRC)/core/ngx_file.c \
           $(NGX_SRC)/core/ngx_crc32.c \
           $(NGX_SRC)/core/ngx_rbtree.c \
           $(NGX_SRC)/core/ngx_murmurhash.c \
           $(NGX_SRC)/os/unix/ngx_alloc.c \
           $(NGX_SRC)/os/unix/ngx_errno.c \
           $(NGX_SRC)/os/unix/ngx_files.c

BUILDDIR = build
NGX_OBJS = $(addprefix $(BUILDDIR)/,$(notdir $(NGX_SRCS:.c=.o)))
LOCAL_OBJS = $(BUILDDIR)/ngx_conf_file.o \
             $(BUILDDIR)/conf_parse.o \
             $(BUILDDIR)/stubs.o \
             $(BUILDDIR)/main.o

TARGET = $(BUILDDIR)/nginx_conf_parse

all: $(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(TARGET): $(NGX_OBJS) $(LOCAL_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

# Patch ngx_conf_file.c at build time: replace ngx_conf_handler with conf_handler
$(BUILDDIR)/ngx_conf_file.c: $(NGX_SRC)/core/ngx_conf_file.c parser/ngx_conf_file.patch | $(BUILDDIR)
	cp $< $@
	patch -p1 $@ parser/ngx_conf_file.patch

$(BUILDDIR)/ngx_conf_file.o: $(BUILDDIR)/ngx_conf_file.c parser/conf_parse.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILDDIR)/%.o: $(NGX_SRC)/core/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILDDIR)/%.o: $(NGX_SRC)/os/unix/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILDDIR)/conf_parse.o: parser/conf_parse.c parser/conf_parse.h | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILDDIR)/stubs.o: parser/stubs.c | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(BUILDDIR)/main.o: parser/main.c parser/conf_parse.h | $(BUILDDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

test: $(TARGET)
	@printf 'worker_processes auto;\nevents { worker_connections 1024; }\nhttp { server { listen 80; location / { root /var/www; } } }\n' > /tmp/_nrs_test.conf
	@$(TARGET) /tmp/_nrs_test.conf | python3 -m json.tool > /dev/null && echo "parser: OK"
	@rm -f /tmp/_nrs_test.conf
	@python3 scan.py --test

clean:
	rm -rf $(BUILDDIR)

.PHONY: all test clean
