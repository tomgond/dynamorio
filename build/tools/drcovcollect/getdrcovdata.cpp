#include "dr_api.h"
#include "drvector.h"
#include "drcovlib.h"
#include <string.h>
#include <stdio.h>
#include <stddef.h>

#define MODULE_FILE_VERSION 5

#define NUM_GLOBAL_MODULE_CACHE 8
#define NUM_THREAD_MODULE_CACHE 4

typedef struct _module_entry_t {
    uint id;
    uint containing_id;
    bool unload; /* if the module is unloaded */
    /* The bounds of the segment, or whole module if it's contiguous. */
    app_pc start;
    app_pc end;
    /* A copy of the data.  Segments of non-contiguous modules all share
     * the same data pointer.
     */
    module_data_t *data;
    void *custom;
    /* The file offset of the segment */
    uint64 offset;
    app_pc preferred_base;
} module_entry_t;

typedef struct _module_table_t {
    /* A vector of entries.  Non-contiguous modules have entries that
     * are consecutive, with the lowest-address (main entry) first.
     */
    drvector_t vector;
    /* for quick query without lock, assuming pointer-aligned */
    module_entry_t *cache[NUM_GLOBAL_MODULE_CACHE];
} module_table_t;

typedef struct _per_thread_t {
    /* for quick per-thread query without lock */
    module_entry_t *cache[NUM_THREAD_MODULE_CACHE];
} per_thread_t;


static int drmodtrack_init_count;
static int tls_idx = -1;
static module_table_t module_table;

/* Custom per-module field support. */
static void *(*module_load_cb)(module_data_t *module, int seg_idx);
static int (*module_print_cb)(void *data, char *dst, size_t max_len);
static const char *(*module_parse_cb)(const char *src, OUT void **data);
static void (*module_free_cb)(void *data);


drcovlib_status_t
drmodtrack_dump(file_t log)
{
    drcovlib_status_t res;
    size_t size = 200 + module_table.vector.entries * (MAXIMUM_PATH + 40);
    char *buf;
    size_t wrote;
    do {
        buf = (char*)dr_global_alloc(size);
        res = drmodtrack_dump_buf(buf, size, &wrote);
        if (res == DRCOVLIB_SUCCESS)
            dr_write_file(log, buf, wrote - 1 /*no null*/);
        dr_global_free(buf, size);
        size *= 2;
    } while (res == DRCOVLIB_ERROR_BUF_TOO_SMALL);
    return res;
}
