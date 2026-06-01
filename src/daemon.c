#include "bloomd.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <math.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t bloomd_stop;
static uint64_t bloomd_now_ms(void);
static int bloomd_validate_open_pinned_map(const struct bloomd_filter_meta *meta, int fd, char *errbuf,
                                           size_t errcap);

struct bloomd_empty_map_pool {
    int map_fd;
    uint64_t capacity;
    uint32_t hashes;
    uint32_t value_size;
};

static struct bloomd_empty_map_pool bloomd_empty_pool = {
    .map_fd = -1,
};

static int bloomd_take_empty_map(struct bloomd_stats *stats, uint64_t capacity, uint32_t hashes,
                                 uint32_t value_size) {
    int fd;

    if (bloomd_empty_pool.map_fd < 0 || bloomd_empty_pool.capacity != capacity ||
        bloomd_empty_pool.hashes != hashes || bloomd_empty_pool.value_size != value_size) {
        if (stats != NULL) {
            stats->empty_pool_misses++;
        }
        return -1;
    }
    if (stats != NULL) {
        stats->empty_pool_hits++;
    }
    fd = bloomd_empty_pool.map_fd;
    bloomd_empty_pool.map_fd = -1;
    bloomd_empty_pool.capacity = 0;
    bloomd_empty_pool.hashes = 0;
    bloomd_empty_pool.value_size = 0;
    return fd;
}

static void bloomd_store_empty_map(int fd, uint64_t capacity, uint32_t hashes, uint32_t value_size) {
    if (fd < 0) {
        return;
    }
    if (bloomd_empty_pool.map_fd >= 0) {
        bloomd_bpf_close(&bloomd_empty_pool.map_fd);
    }
    bloomd_empty_pool.map_fd = fd;
    bloomd_empty_pool.capacity = capacity;
    bloomd_empty_pool.hashes = hashes;
    bloomd_empty_pool.value_size = value_size;
}

static void bloomd_close_empty_pool(void) {
    if (bloomd_empty_pool.map_fd >= 0) {
        bloomd_bpf_close(&bloomd_empty_pool.map_fd);
    }
    bloomd_empty_pool.capacity = 0;
    bloomd_empty_pool.hashes = 0;
    bloomd_empty_pool.value_size = 0;
}

static void bloomd_on_signal(int signo) {
    (void)signo;
    bloomd_stop = 1;
}

static int bloomd_install_signal_handlers(void) {
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = bloomd_on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        return -errno;
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        return -errno;
    }
    return 0;
}

static void bloomd_stderr(const char *msg) {
    fprintf(stderr, "bloomd: %s\n", msg);
}

static void bloomd_logf(const char *level, const char *fmt, ...) {
    va_list ap;

    fprintf(stderr, "bloomd: %s: ", level);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static int bloomd_socket_parent(const char *socket_path, char *parent, size_t parent_sz) {
    size_t len = strlen(socket_path);

    if (len >= parent_sz) {
        return -ENAMETOOLONG;
    }
    memcpy(parent, socket_path, len + 1);
    for (char *p = parent + len; p > parent; --p) {
        if (*p == '/') {
            *p = '\0';
            return 0;
        }
    }
    return -EINVAL;
}

static int bloomd_prepare_roots(const struct bloomd_config *cfg, char *errbuf, size_t errcap) {
    int rc;
    char socket_parent[PATH_MAX];

    rc = bloomd_socket_parent(cfg->socket_path, socket_parent, sizeof(socket_parent));
    if (rc != 0) {
        snprintf(errbuf, errcap, "invalid socket path");
        return rc;
    }
    rc = bloomd_ensure_dir(socket_parent, 0755, true);
    if (rc != 0) {
        snprintf(errbuf, errcap, "could not create socket directory");
        return rc;
    }
    rc = bloomd_ensure_dir(cfg->meta_root, 0755, true);
    if (rc != 0) {
        snprintf(errbuf, errcap, "could not create metadata directory");
        return rc;
    }
    rc = bloomd_ensure_dir(cfg->pin_root, 0755, true);
    if (rc != 0) {
        snprintf(errbuf, errcap, "could not create pin directory");
        return rc;
    }
    if (!bloomd_is_bpffs(cfg->pin_root)) {
        snprintf(errbuf, errcap, "pin root is not on bpffs");
        return -EINVAL;
    }
    bloomd_logf("info", "runtime roots ready socket=%s meta_root=%s pin_root=%s socket_mode=%03o",
                cfg->socket_path, cfg->meta_root, cfg->pin_root, (unsigned)cfg->socket_mode);
    return 0;
}

static bool bloomd_has_suffix(const char *name, const char *suffix) {
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(suffix);

    if (name_len < suffix_len) {
        return false;
    }
    return strcmp(name + name_len - suffix_len, suffix) == 0;
}

static int bloomd_meta_entry_name(const char *entry, char out[BLOOMD_MAX_NAME_LEN + 1]) {
    size_t len = strlen(entry);

    if (!bloomd_has_suffix(entry, ".meta")) {
        return -EINVAL;
    }
    len -= strlen(".meta");
    if (len == 0 || len > BLOOMD_MAX_NAME_LEN) {
        return -EINVAL;
    }
    memcpy(out, entry, len);
    out[len] = '\0';
    return bloomd_name_is_valid(out) ? 0 : -EINVAL;
}

static bool bloomd_path_has_name(const char *path, const char *name) {
    const char *slash = strrchr(path, '/');

    if (slash == NULL) {
        return false;
    }
    return strcmp(slash + 1, name) == 0;
}

static bool bloomd_path_under_root(const char *path, const char *root) {
    size_t root_len = strlen(root);

    return strncmp(path, root, root_len) == 0 &&
           (path[root_len] == '/' || path[root_len] == '\0');
}

static int bloomd_assign_filter_paths(const struct bloomd_config *cfg, struct bloomd_filter_meta *meta) {
    int rc;

    rc = bloomd_build_meta_path(cfg->meta_root, meta->name, meta->meta_path, sizeof(meta->meta_path));
    if (rc != 0) {
        return rc;
    }
    rc = bloomd_build_log_path(cfg->meta_root, meta->name, meta->log_path, sizeof(meta->log_path));
    if (rc != 0) {
        return rc;
    }
    return bloomd_build_pin_path(cfg->pin_root, meta->name, meta->pin_path, sizeof(meta->pin_path));
}

struct bloomd_replay_ctx {
    int map_fd;
    int rc;
    char *errbuf;
    size_t errcap;
};

static int bloomd_replay_digest_cb(const uint8_t digest[BLOOMD_DIGEST_SIZE], void *ctx_void) {
    struct bloomd_replay_ctx *ctx = ctx_void;

    ctx->rc = bloomd_bpf_add_digest(ctx->map_fd, digest, ctx->errbuf, ctx->errcap);
    return ctx->rc == 0 ? 0 : -1;
}

static int bloomd_rebuild_from_log(const struct bloomd_config *cfg, struct bloomd_filter_meta *meta,
                                   int *map_fd_out, uint64_t *replayed_out, char *errbuf,
                                   size_t errcap) {
    struct bloomd_replay_ctx ctx;
    uint64_t replayed = 0;
    int map_fd = -1;
    int rc;

    rc = bloomd_assign_filter_paths(cfg, meta);
    if (rc != 0) {
        snprintf(errbuf, errcap, "failed to build filter paths for %s", meta->name);
        return rc;
    }
    rc = bloomd_bpf_create_map(meta->name, meta->capacity, meta->hashes, &map_fd, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }
    memset(&ctx, 0, sizeof(ctx));
    ctx.map_fd = map_fd;
    ctx.errbuf = errbuf;
    ctx.errcap = errcap;
    rc = bloomd_log_replay(meta->log_path, bloomd_replay_digest_cb, &ctx, &replayed);
    if (rc != 0) {
        bloomd_bpf_close(&map_fd);
        if (ctx.rc != 0) {
            return ctx.rc;
        }
        if (rc == -ENOENT) {
            snprintf(errbuf, errcap, "digest log missing for %s", meta->name);
        } else if (rc == -EINVAL) {
            snprintf(errbuf, errcap, "digest log is malformed for %s", meta->name);
        } else {
            snprintf(errbuf, errcap, "failed to replay digest log for %s: %s", meta->name,
                     strerror(-rc));
        }
        return rc;
    }
    rc = bloomd_bpf_pin_map(map_fd, meta->pin_path, errbuf, errcap);
    if (rc != 0) {
        bloomd_bpf_close(&map_fd);
        return rc;
    }
    if (replayed_out != NULL) {
        *replayed_out = replayed;
    }
    *map_fd_out = map_fd;
    return 0;
}

static int bloomd_open_filter_log(struct bloomd_filter *filter, bool truncate, char *errbuf, size_t errcap) {
    filter->log_fd = truncate ? bloomd_log_open_create(filter->meta.log_path)
                              : bloomd_log_open_append(filter->meta.log_path);
    if (filter->log_fd < 0) {
        snprintf(errbuf, errcap, "failed to open digest log for %s: %s", filter->meta.name,
                 strerror(-filter->log_fd));
        return filter->log_fd;
    }
    filter->log_buf_len = 0;
    filter->log_dirty = false;
    filter->last_log_sync_ms = bloomd_now_ms();
    return 0;
}

static int bloomd_update_filter_meta_state(struct bloomd_filter *filter, bool has_data, bool log_clean,
                                           char *errbuf, size_t errcap) {
    struct bloomd_filter_meta updated = filter->meta;
    int rc;

    updated.has_data = has_data;
    updated.log_clean = log_clean;
    rc = bloomd_meta_write_atomic(&updated);
    if (rc != 0) {
        if (errbuf != NULL && errcap > 0) {
            snprintf(errbuf, errcap, "failed to write metadata");
        }
        return rc;
    }
    filter->meta = updated;
    return 0;
}

static int bloomd_ensure_filter_durable(struct bloomd_filter *filter, char *errbuf, size_t errcap) {
    int rc;

    if (filter->meta.has_data) {
        if (filter->log_fd < 0) {
            return bloomd_open_filter_log(filter, false, errbuf, errcap);
        }
        return 0;
    }
    rc = bloomd_bpf_pin_map(filter->map_fd, filter->meta.pin_path, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }
    rc = bloomd_open_filter_log(filter, true, errbuf, errcap);
    if (rc != 0) {
        (void)bloomd_bpf_unpin(filter->meta.pin_path, NULL, 0);
        return rc;
    }
    rc = bloomd_update_filter_meta_state(filter, true, true, errbuf, errcap);
    if (rc != 0) {
        bloomd_log_close(&filter->log_fd, false);
        (void)bloomd_log_delete(filter->meta.log_path);
        (void)bloomd_bpf_unpin(filter->meta.pin_path, NULL, 0);
        return rc;
    }
    return 0;
}

static int bloomd_mark_filter_log_dirty(struct bloomd_filter *filter, bool *changed_out, char *errbuf,
                                        size_t errcap) {
    int rc;

    *changed_out = false;
    if (!filter->meta.has_data || !filter->meta.log_clean) {
        return 0;
    }
    rc = bloomd_update_filter_meta_state(filter, true, false, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }
    *changed_out = true;
    return 0;
}

static void bloomd_sync_dirty_logs(struct bloomd_filter_set *set, uint64_t now_ms, bool force) {
    for (size_t i = 0; i < set->len; ++i) {
        struct bloomd_filter *filter = &set->items[i];
        int rc;

        if (!filter->log_dirty) {
            continue;
        }
        if (!force && now_ms - filter->last_log_sync_ms < BLOOMD_LOG_SYNC_INTERVAL_MS) {
            continue;
        }
        rc = bloomd_log_buffer_flush(filter->log_fd, filter->log_buf, &filter->log_buf_len, true);
        filter->last_log_sync_ms = now_ms;
        if (rc != 0) {
            bloomd_logf("warn", "failed to sync digest log name=%s path=%s: %s", filter->meta.name,
                        filter->meta.log_path, strerror(-rc));
            continue;
        }
        filter->log_dirty = false;
        if (filter->meta.has_data && !filter->meta.log_clean) {
            rc = bloomd_update_filter_meta_state(filter, true, true, NULL, 0);
            if (rc != 0) {
                bloomd_logf("warn", "failed to mark digest log clean name=%s path=%s: %s",
                            filter->meta.name, filter->meta.meta_path, strerror(-rc));
                continue;
            }
        }
    }
}

static int bloomd_load_metadata_dir(const struct bloomd_config *cfg, struct bloomd_filter_set *set,
                                    struct bloomd_stats *stats, char *errbuf, size_t errcap) {
    char **entries = NULL;
    size_t count = 0;
    int rc;

    rc = bloomd_list_dir(cfg->meta_root, &entries, &count);
    if (rc != 0 && rc != -ENOENT) {
        snprintf(errbuf, errcap, "failed to list metadata directory");
        return rc;
    }
    for (size_t i = 0; i < count; ++i) {
        struct bloomd_filter_meta meta;
        struct bloomd_filter filter;
        char path[PATH_MAX];
        char entry_name[BLOOMD_MAX_NAME_LEN + 1];
        int fd = -1;
        bool unpin_on_error = false;
        bool next = false;

        memset(&filter, 0, sizeof(filter));
        filter.log_fd = -1;

        if (!bloomd_has_suffix(entries[i], ".meta")) {
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", cfg->meta_root, entries[i]) >= (int)sizeof(path)) {
            continue;
        }
        rc = bloomd_meta_entry_name(entries[i], entry_name);
        if (rc != 0) {
            bloomd_logf("warn", "ignoring malformed metadata filename path=%s", path);
            continue;
        }
        rc = bloomd_meta_read_file(path, &meta);
        if (rc != 0) {
            bloomd_logf("warn", "recovering invalid metadata path=%s", path);
            (void)bloomd_meta_recover_stale(path);
            stats->orphan_meta++;
            continue;
        }
        if (strcmp(meta.name, entry_name) != 0) {
            bloomd_logf("warn", "recovering metadata with mismatched name path=%s meta_name=%s expected=%s",
                        path, meta.name, entry_name);
            (void)bloomd_meta_recover_stale(path);
            stats->orphan_meta++;
            continue;
        }
        if (!bloomd_path_under_root(meta.pin_path, cfg->pin_root) ||
            !bloomd_path_has_name(meta.pin_path, meta.name)) {
            bloomd_logf("warn", "recovering metadata with mismatched pin path path=%s pin_path=%s", path,
                        meta.pin_path);
            (void)bloomd_meta_recover_stale(path);
            stats->orphan_meta++;
            continue;
        }
        rc = bloomd_build_log_path(cfg->meta_root, meta.name, meta.log_path, sizeof(meta.log_path));
        if (rc != 0) {
            snprintf(errbuf, errcap, "failed to derive digest log path for %s", meta.name);
            goto cleanup_entry;
        }
        fd = bloomd_bpf_open_pinned(meta.pin_path);
        if (fd < 0) {
            if (fd == -ENOENT) {
                uint64_t replayed = 0;

                if (!meta.has_data) {
                    rc = bloomd_bpf_create_map(meta.name, meta.capacity, meta.hashes, &fd, errbuf, errcap);
                    if (rc == 0) {
                        bloomd_logf("warn", "rebuilt empty filter from metadata name=%s missing_pin=%s",
                                    meta.name, meta.pin_path);
                    } else {
                        goto cleanup_entry;
                    }
                } else if (!meta.log_clean) {
                    snprintf(errbuf, errcap,
                             "refusing rebuild for %s: replay log may be missing unsynced tail", meta.name);
                    rc = -EUCLEAN;
                    goto cleanup_entry;
                } else {
                    rc = bloomd_rebuild_from_log(cfg, &meta, &fd, &replayed, errbuf, errcap);
                    if (rc == 0) {
                        unpin_on_error = true;
                        bloomd_logf("warn",
                                    "rebuilt missing pinned map from digest log name=%s log=%s replayed=%llu",
                                    meta.name, meta.log_path, (unsigned long long)replayed);
                    } else if (rc == -ENOENT) {
                        bloomd_logf("warn", "recovering stale metadata path=%s missing_pin=%s missing_log=%s",
                                    path, meta.pin_path, meta.log_path);
                        (void)bloomd_meta_recover_stale(path);
                        stats->orphan_meta++;
                        continue;
                    } else {
                        goto cleanup_entry;
                    }
                }
            }
            if (fd < 0) {
                snprintf(errbuf, errcap, "failed to open pinned map for %s: %s", meta.name,
                         strerror(-fd));
                rc = fd;
                goto cleanup_entry;
            }
        }
        rc = bloomd_validate_open_pinned_map(&meta, fd, errbuf, errcap);
        if (rc != 0) {
            goto cleanup_entry;
        }
        if (bloomd_filter_set_find(set, meta.name) != NULL) {
            bloomd_logf("warn", "recovering duplicate metadata entry path=%s name=%s", path, meta.name);
            (void)bloomd_meta_recover_stale(path);
            stats->orphan_meta++;
            next = true;
            goto cleanup_entry;
        }
        filter.meta = meta;
        filter.map_fd = fd;
        if (filter.meta.has_data) {
            rc = bloomd_open_filter_log(&filter, false, errbuf, errcap);
            if (rc != 0) {
                goto cleanup_entry;
            }
        }
        rc = bloomd_filter_set_add(set, &filter);
        if (rc != 0) {
            snprintf(errbuf, errcap, "too many filters loaded");
            goto cleanup_entry;
        }
        fd = -1;
        filter.log_fd = -1;
        bloomd_logf("info", "loaded filter name=%s pin=%s meta=%s", meta.name, meta.pin_path, meta.meta_path);
        stats->filters_loaded++;
        continue;

cleanup_entry:
        bloomd_log_close(&filter.log_fd, false);
        if (unpin_on_error) {
            (void)bloomd_bpf_unpin(meta.pin_path, NULL, 0);
        }
        bloomd_bpf_close(&fd);
        if (next) {
            continue;
        }
        bloomd_free_name_list(entries, count);
        return rc;
    }
    bloomd_free_name_list(entries, count);
    return 0;
}

static int bloomd_cleanup_orphan_pins(const struct bloomd_config *cfg, struct bloomd_filter_set *set,
                                      struct bloomd_stats *stats) {
    char **entries = NULL;
    size_t count = 0;
    int rc;

    rc = bloomd_list_dir(cfg->pin_root, &entries, &count);
    if (rc != 0 && rc != -ENOENT) {
        return rc;
    }
    for (size_t i = 0; i < count; ++i) {
        char path[PATH_MAX];

        if (!bloomd_name_is_valid(entries[i])) {
            bloomd_logf("warn", "ignoring unexpected pin entry name=%s", entries[i]);
            continue;
        }
        if (bloomd_filter_set_find(set, entries[i]) != NULL) {
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", cfg->pin_root, entries[i]) >= (int)sizeof(path)) {
            continue;
        }
        if (unlink(path) == 0) {
            bloomd_logf("warn", "removed orphan pin path=%s", path);
            stats->orphan_pin++;
        }
    }
    bloomd_free_name_list(entries, count);
    return 0;
}

static int bloomd_validate_open_pinned_map(const struct bloomd_filter_meta *meta, int fd, char *errbuf,
                                           size_t errcap) {
    struct bloomd_bpf_map_info info;
    int rc;

    rc = bloomd_bpf_get_map_info(fd, &info, errbuf, errcap);
    if (rc != 0) {
        return rc;
    }
    if (info.type != BPF_MAP_TYPE_BLOOM_FILTER || info.key_size != 0 ||
        info.value_size != meta->value_size || info.max_entries != meta->capacity ||
        (info.map_extra & 0x0fU) != meta->hashes) {
        if (errbuf != NULL && errcap > 0) {
            snprintf(errbuf, errcap, "pinned map parameters do not match metadata for %s", meta->name);
        }
        return -EINVAL;
    }
    return 0;
}

static int bloomd_send_bool(struct bloomd_response *resp, bool value) {
    uint8_t flag = value ? 1U : 0U;

    return bloomd_buffer_append(&resp->body, &flag, sizeof(flag));
}

static int bloomd_send_u32_count_bytes(struct bloomd_response *resp, uint16_t count,
                                       const uint8_t *values) {
    int rc = bloomd_buffer_append_u16(&resp->body, count);

    if (rc != 0) {
        return rc;
    }
    return bloomd_buffer_append(&resp->body, values, count);
}

static int bloomd_name_view_is_valid(const uint8_t *src, uint16_t len) {
    if (len == 0 || len > BLOOMD_MAX_NAME_LEN) {
        return -EINVAL;
    }
    for (uint16_t i = 0; i < len; ++i) {
        const unsigned char ch = src[i];

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_') {
            continue;
        }
        return -EINVAL;
    }
    return 0;
}

static int bloomd_parse_name_copy(const uint8_t *src, uint16_t len, char out[BLOOMD_MAX_NAME_LEN + 1]) {
    if (bloomd_name_view_is_valid(src, len) != 0) {
        return -EINVAL;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return 0;
}

static int bloomd_handle_ping(struct bloomd_response *resp) {
    return bloomd_buffer_append_str(&resp->body, "PONG");
}

struct bloomd_log_stage {
    size_t prev_buf_len;
    off_t prev_file_size;
    bool prev_dirty;
    bool can_truncate;
    bool overflow_flush;
};

static int bloomd_stage_digest_for_add(struct bloomd_filter *filter,
                                       const uint8_t digest[BLOOMD_DIGEST_SIZE],
                                       enum bloomd_log_sync_mode log_sync_mode,
                                       struct bloomd_log_stage *stage) {
    int rc;

    memset(stage, 0, sizeof(*stage));
    stage->prev_buf_len = filter->log_buf_len;
    stage->prev_dirty = filter->log_dirty;
    stage->overflow_flush =
        filter->log_buf_len + BLOOMD_DIGEST_SIZE > BLOOMD_LOG_BUFFER_CAP;
    if (log_sync_mode == BLOOMD_LOG_SYNC_ALWAYS) {
        stage->prev_file_size = lseek(filter->log_fd, 0, SEEK_END);
        if (stage->prev_file_size < 0) {
            return -errno;
        }
        stage->can_truncate = true;
    }

    rc = bloomd_log_buffer_append(filter->log_fd, filter->log_buf, &filter->log_buf_len, digest);
    if (rc != 0) {
        return rc;
    }
    if (log_sync_mode == BLOOMD_LOG_SYNC_ALWAYS) {
        rc = bloomd_log_buffer_flush(filter->log_fd, filter->log_buf, &filter->log_buf_len, true);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static void bloomd_rollback_staged_digest(struct bloomd_filter *filter,
                                          const struct bloomd_log_stage *stage,
                                          enum bloomd_log_sync_mode log_sync_mode) {
    if (log_sync_mode == BLOOMD_LOG_SYNC_ALWAYS) {
        if (stage->can_truncate) {
            (void)bloomd_log_truncate(filter->log_fd, stage->prev_file_size, true);
        }
        filter->log_buf_len = 0;
        filter->log_dirty = false;
        return;
    }
    filter->log_buf_len = stage->overflow_flush ? 0 : stage->prev_buf_len;
    filter->log_dirty = stage->prev_dirty;
}

static void bloomd_commit_staged_digest(struct bloomd_filter *filter,
                                        enum bloomd_log_sync_mode log_sync_mode) {
    if (log_sync_mode == BLOOMD_LOG_SYNC_ALWAYS) {
        filter->log_dirty = false;
        filter->last_log_sync_ms = bloomd_now_ms();
    } else {
        filter->log_dirty = true;
    }
}

static int bloomd_handle_create(const struct bloomd_config *cfg, struct bloomd_filter_set *set,
                                struct bloomd_stats *stats, const struct bloomd_request_view *req,
                                struct bloomd_response *resp) {
    struct bloomd_create_request hdr;
    struct bloomd_filter filter;
    char name[BLOOMD_MAX_NAME_LEN + 1];
    char errbuf[256];
    int rc;

    if (req->header.body_len < sizeof(hdr)) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "short CREATE body");
    }
    memcpy(&hdr, req->body, sizeof(hdr));
    if (sizeof(hdr) + hdr.name_len != req->header.body_len) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "malformed CREATE body");
    }
    if (hdr.reserved != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "CREATE reserved field must be zero");
    }
    rc = bloomd_parse_name_copy(req->body + sizeof(hdr), hdr.name_len, name);
    if (rc != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NAME, BLOOMD_ERR_PARSE, "invalid name");
    }
    if (hdr.capacity == 0 || hdr.capacity > UINT32_MAX || hdr.hashes > 15U ||
        !isfinite(hdr.error_rate) || hdr.error_rate <= 0.0 || hdr.error_rate >= 1.0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_RANGE,
                                     "invalid capacity, error_rate, or hashes");
    }
    if (bloomd_filter_set_find(set, name) != NULL) {
        return bloomd_response_error(resp, BLOOMD_STATUS_EXISTS, BLOOMD_ERR_NONE,
                                     "filter already exists");
    }
    memset(&filter, 0, sizeof(filter));
    filter.map_fd = -1;
    filter.log_fd = -1;
    snprintf(filter.meta.name, sizeof(filter.meta.name), "%s", name);
    snprintf(filter.meta.backend, sizeof(filter.meta.backend), "%s", BLOOMD_BACKEND_NAME);
    snprintf(filter.meta.digest, sizeof(filter.meta.digest), "%s", BLOOMD_DIGEST_NAME);
    filter.meta.capacity = hdr.capacity;
    filter.meta.error_rate = hdr.error_rate;
    filter.meta.hashes = hdr.hashes == 0 ? bloomd_hashes_for_error_rate(hdr.error_rate) : hdr.hashes;
    filter.meta.value_size = BLOOMD_DIGEST_SIZE;
    filter.meta.metadata_version = BLOOMD_METADATA_VERSION;
    filter.meta.has_data = false;
    filter.meta.log_clean = true;
    rc = bloomd_assign_filter_paths(cfg, &filter.meta);
    if (rc != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_INTERNAL, BLOOMD_ERR_NONE,
                                     "failed to build filter paths");
    }

    filter.map_fd = bloomd_take_empty_map(stats, filter.meta.capacity, filter.meta.hashes,
                                          filter.meta.value_size);
    if (filter.map_fd < 0) {
        rc = bloomd_bpf_create_map(name, filter.meta.capacity, filter.meta.hashes, &filter.map_fd, errbuf,
                                   sizeof(errbuf));
        if (rc != 0) {
            return bloomd_response_error(resp, rc == -EPERM ? BLOOMD_STATUS_PERM : BLOOMD_STATUS_BPF,
                                         rc == -EPERM ? BLOOMD_ERR_BPF_PRIVS : BLOOMD_ERR_UNSUPPORTED_KERNEL,
                                         errbuf);
        }
    }
    rc = bloomd_meta_write_atomic(&filter.meta);
    if (rc != 0) {
        bloomd_bpf_close(&filter.map_fd);
        return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA,
                                     "failed to write metadata");
    }
    rc = bloomd_filter_set_add(set, &filter);
    if (rc != 0) {
        bloomd_meta_delete(filter.meta.meta_path);
        bloomd_log_close(&filter.log_fd, false);
        bloomd_log_delete(filter.meta.log_path);
        bloomd_bpf_unpin(filter.meta.pin_path, NULL, 0);
        bloomd_bpf_close(&filter.map_fd);
        return bloomd_response_error(resp, BLOOMD_STATUS_INTERNAL, BLOOMD_ERR_NONE,
                                     "too many filters");
    }
    stats->filters_created++;
    return 0;
}

static int bloomd_parse_name_payload(const struct bloomd_request_view *req,
                                     struct bloomd_payload_request *hdr_out,
                                     const char **name_out, uint16_t *name_len_out,
                                     const uint8_t **payload_out) {
    struct bloomd_payload_request hdr;
    const uint8_t *name;

    if (req->header.body_len < sizeof(hdr)) {
        return -EINVAL;
    }
    memcpy(&hdr, req->body, sizeof(hdr));
    if ((uint64_t)sizeof(hdr) + hdr.name_len + hdr.payload_len != req->header.body_len) {
        return -EINVAL;
    }
    if (hdr.reserved0 != 0) {
        return -EINVAL;
    }
    name = req->body + sizeof(hdr);
    if (bloomd_name_view_is_valid(name, hdr.name_len) != 0) {
        return -EINVAL;
    }
    *payload_out = req->body + sizeof(hdr) + hdr.name_len;
    *name_out = (const char *)name;
    *name_len_out = hdr.name_len;
    *hdr_out = hdr;
    return 0;
}

static int bloomd_handle_add_check(struct bloomd_filter_set *set, struct bloomd_filter *filter,
                                   const struct bloomd_request_view *req, struct bloomd_response *resp,
                                   bool is_add, enum bloomd_log_sync_mode log_sync_mode) {
    struct bloomd_payload_request hdr;
    const char *name;
    uint16_t name_len;
    const uint8_t *payload;
    uint8_t digest[BLOOMD_DIGEST_SIZE];
    struct bloomd_log_stage stage;
    char errbuf[256];
    bool present = false;
    bool meta_marked_dirty = false;
    int rc;

    rc = bloomd_parse_name_payload(req, &hdr, &name, &name_len, &payload);
    if (rc != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "malformed body");
    }
    filter = bloomd_filter_set_find_n(set, name, name_len);
    if (filter == NULL) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NOT_FOUND, BLOOMD_ERR_NONE,
                                     "filter not found");
    }
    bloomd_digest_payload(payload, hdr.payload_len, digest);
    if (is_add) {
        rc = bloomd_ensure_filter_durable(filter, errbuf, sizeof(errbuf));
        if (rc != 0) {
            return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA, errbuf);
        }
        if (log_sync_mode == BLOOMD_LOG_SYNC_PERIODIC) {
            rc = bloomd_mark_filter_log_dirty(filter, &meta_marked_dirty, errbuf, sizeof(errbuf));
            if (rc != 0) {
                return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA, errbuf);
            }
        }
        rc = bloomd_stage_digest_for_add(filter, digest, log_sync_mode, &stage);
        if (rc != 0) {
            if (meta_marked_dirty) {
                (void)bloomd_update_filter_meta_state(filter, true, true, NULL, 0);
            }
            return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA,
                                         log_sync_mode == BLOOMD_LOG_SYNC_ALWAYS
                                             ? "failed to sync digest log"
                                             : "failed to append digest log");
        }
        rc = bloomd_bpf_add_digest(filter->map_fd, digest, errbuf, sizeof(errbuf));
        if (rc != 0) {
            bloomd_rollback_staged_digest(filter, &stage, log_sync_mode);
            if (meta_marked_dirty) {
                (void)bloomd_update_filter_meta_state(filter, true, true, NULL, 0);
            }
            return bloomd_response_error(resp, BLOOMD_STATUS_BPF, BLOOMD_ERR_NONE, errbuf);
        }
        bloomd_commit_staged_digest(filter, log_sync_mode);
        filter->add_calls++;
        present = true;
    } else {
        rc = bloomd_bpf_check_digest(filter->map_fd, digest, &present, errbuf, sizeof(errbuf));
        if (rc != 0) {
            return bloomd_response_error(resp, BLOOMD_STATUS_BPF, BLOOMD_ERR_NONE, errbuf);
        }
        filter->check_calls++;
    }
    return bloomd_send_bool(resp, present);
}

static int bloomd_parse_batch(const struct bloomd_request_view *req, struct bloomd_batch_request *hdr_out,
                              const char **name_out, uint16_t *name_len_out,
                              const uint8_t **items_out, size_t *items_len_out) {
    struct bloomd_batch_request hdr;
    const uint8_t *name;

    if (req->header.body_len < sizeof(hdr)) {
        return -EINVAL;
    }
    memcpy(&hdr, req->body, sizeof(hdr));
    if (hdr.item_count == 0) {
        return -EINVAL;
    }
    if (hdr.item_count > BLOOMD_MAX_BATCH_ITEMS) {
        return -E2BIG;
    }
    if (hdr.reserved != 0) {
        return -EINVAL;
    }
    if (req->header.body_len < sizeof(hdr) + hdr.name_len) {
        return -EINVAL;
    }
    name = req->body + sizeof(hdr);
    if (bloomd_name_view_is_valid(name, hdr.name_len) != 0) {
        return -EINVAL;
    }
    *items_out = req->body + sizeof(hdr) + hdr.name_len;
    *items_len_out = req->header.body_len - sizeof(hdr) - hdr.name_len;
    *name_out = (const char *)name;
    *name_len_out = hdr.name_len;
    *hdr_out = hdr;
    return 0;
}

static int bloomd_handle_batch(struct bloomd_filter_set *set, const struct bloomd_request_view *req,
                               struct bloomd_response *resp, bool is_add,
                               enum bloomd_log_sync_mode log_sync_mode) {
    struct bloomd_batch_request hdr;
    const char *name;
    uint16_t name_len;
    const uint8_t *items;
    size_t items_len;
    struct bloomd_filter *filter;
    uint8_t results[BLOOMD_MAX_BATCH_ITEMS];
    size_t off = 0;
    char errbuf[256];
    bool any_added_success = false;
    bool meta_marked_dirty = false;
    int rc;

    rc = bloomd_parse_batch(req, &hdr, &name, &name_len, &items, &items_len);
    if (rc != 0) {
        return bloomd_response_error(resp, rc == -E2BIG ? BLOOMD_STATUS_TOO_LARGE
                                                        : BLOOMD_STATUS_BAD_REQUEST,
                                     rc == -E2BIG ? BLOOMD_ERR_RANGE : BLOOMD_ERR_PARSE,
                                     rc == -E2BIG ? "batch item count exceeds protocol limit"
                                                  : "malformed batch body");
    }
    filter = bloomd_filter_set_find_n(set, name, name_len);
    if (filter == NULL) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NOT_FOUND, BLOOMD_ERR_NONE,
                                     "filter not found");
    }
    if (is_add) {
        size_t scan = 0;
        for (uint16_t i = 0; i < hdr.item_count; ++i) {
            const uint8_t *scan_payload;
            uint32_t scan_payload_len;
            size_t scan_consumed;
            rc = bloomd_protocol_read_payload(items + scan, items_len - scan, &scan_payload,
                                              &scan_payload_len, &scan_consumed);
            if (rc != 0) {
                return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                             "malformed batch payload");
            }
            scan += scan_consumed;
        }
        if (scan != items_len) {
            return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                         "batch body has trailing bytes");
        }
        rc = bloomd_ensure_filter_durable(filter, errbuf, sizeof(errbuf));
        if (rc != 0) {
            return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA, errbuf);
        }
        if (log_sync_mode == BLOOMD_LOG_SYNC_PERIODIC) {
            rc = bloomd_mark_filter_log_dirty(filter, &meta_marked_dirty, errbuf, sizeof(errbuf));
            if (rc != 0) {
                return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA, errbuf);
            }
        }
    }
    for (uint16_t i = 0; i < hdr.item_count; ++i) {
        const uint8_t *payload;
        uint32_t payload_len;
        uint8_t digest[BLOOMD_DIGEST_SIZE];
        struct bloomd_log_stage stage;
        bool present = false;
        size_t consumed;

        rc = bloomd_protocol_read_payload(items + off, items_len - off, &payload, &payload_len,
                                          &consumed);
        if (rc != 0) {
            return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                         "malformed batch payload");
        }
        bloomd_digest_payload(payload, payload_len, digest);
        if (is_add) {
            rc = bloomd_stage_digest_for_add(filter, digest, log_sync_mode, &stage);
            if (rc != 0) {
                if (meta_marked_dirty && !any_added_success) {
                    (void)bloomd_update_filter_meta_state(filter, true, true, NULL, 0);
                }
                return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA,
                                             log_sync_mode == BLOOMD_LOG_SYNC_ALWAYS
                                                 ? "failed to sync digest log"
                                                 : "failed to append digest log");
            }
            rc = bloomd_bpf_add_digest(filter->map_fd, digest, errbuf, sizeof(errbuf));
            if (rc != 0) {
                bloomd_rollback_staged_digest(filter, &stage, log_sync_mode);
                if (meta_marked_dirty && !any_added_success) {
                    (void)bloomd_update_filter_meta_state(filter, true, true, NULL, 0);
                }
                return bloomd_response_error(resp, BLOOMD_STATUS_BPF, BLOOMD_ERR_NONE, errbuf);
            }
            bloomd_commit_staged_digest(filter, log_sync_mode);
            present = true;
            any_added_success = true;
        } else {
            rc = bloomd_bpf_check_digest(filter->map_fd, digest, &present, errbuf, sizeof(errbuf));
            if (rc != 0) {
                return bloomd_response_error(resp, BLOOMD_STATUS_BPF, BLOOMD_ERR_NONE, errbuf);
            }
        }
        results[i] = present ? 1U : 0U;
        off += consumed;
    }
    if (off != items_len) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "batch body has trailing bytes");
    }
    if (is_add) {
        filter->batch_add_calls++;
    } else {
        filter->batch_check_calls++;
    }
    return bloomd_send_u32_count_bytes(resp, hdr.item_count, results);
}

static int bloomd_handle_info(struct bloomd_filter_set *set, const struct bloomd_request_view *req,
                              struct bloomd_response *resp) {
    struct bloomd_name_request hdr;
    const char *name;
    struct bloomd_filter *filter;
    uint16_t name_len;
    uint16_t backend_len;
    uint16_t digest_len;
    uint32_t pin_len;
    uint32_t state_flags;
    int rc;

    if (req->header.body_len < sizeof(hdr)) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "short INFO body");
    }
    memcpy(&hdr, req->body, sizeof(hdr));
    if (sizeof(hdr) + hdr.name_len != req->header.body_len) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "malformed INFO body");
    }
    if (hdr.reserved0 != 0 || hdr.reserved1 != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "INFO reserved fields must be zero");
    }
    name = (const char *)(req->body + sizeof(hdr));
    if (bloomd_name_view_is_valid((const uint8_t *)name, hdr.name_len) != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NAME, BLOOMD_ERR_PARSE, "invalid name");
    }
    filter = bloomd_filter_set_find_n(set, name, hdr.name_len);
    if (filter == NULL) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NOT_FOUND, BLOOMD_ERR_NONE,
                                     "filter not found");
    }
    name_len = (uint16_t)strlen(filter->meta.name);
    backend_len = (uint16_t)strlen(filter->meta.backend);
    digest_len = (uint16_t)strlen(filter->meta.digest);
    pin_len = (uint32_t)strlen(filter->meta.pin_path);
    state_flags = filter->meta.has_data ? BLOOMD_FILTER_STATE_DURABLE
                                        : BLOOMD_FILTER_STATE_METADATA_ONLY;
    if (filter->meta.log_clean) {
        state_flags |= BLOOMD_FILTER_STATE_LOG_CLEAN;
    } else if (filter->meta.has_data) {
        state_flags |= BLOOMD_FILTER_STATE_LOG_DIRTY;
    }

    rc = bloomd_buffer_append_u16(&resp->body, name_len);
    rc |= bloomd_buffer_append_u16(&resp->body, backend_len);
    rc |= bloomd_buffer_append_u16(&resp->body, digest_len);
    rc |= bloomd_buffer_append_u16(&resp->body, 0);
    rc |= bloomd_buffer_append_u64(&resp->body, filter->meta.capacity);
    rc |= bloomd_buffer_append_double(&resp->body, filter->meta.error_rate);
    rc |= bloomd_buffer_append_u32(&resp->body, filter->meta.hashes);
    rc |= bloomd_buffer_append_u32(&resp->body, filter->meta.value_size);
    rc |= bloomd_buffer_append_u64(&resp->body, filter->add_calls);
    rc |= bloomd_buffer_append_u64(&resp->body, filter->check_calls);
    rc |= bloomd_buffer_append_u64(&resp->body, filter->batch_add_calls);
    rc |= bloomd_buffer_append_u64(&resp->body, filter->batch_check_calls);
    rc |= bloomd_buffer_append_u32(&resp->body, pin_len);
    rc |= bloomd_buffer_append_u32(&resp->body, state_flags);
    rc |= bloomd_buffer_append(&resp->body, filter->meta.name, name_len);
    rc |= bloomd_buffer_append(&resp->body, filter->meta.backend, backend_len);
    rc |= bloomd_buffer_append(&resp->body, filter->meta.digest, digest_len);
    rc |= bloomd_buffer_append(&resp->body, filter->meta.pin_path, pin_len);
    return rc;
}

static void bloomd_count_filter_states(const struct bloomd_filter_set *set, uint32_t *metadata_only_out,
                                       uint32_t *durable_clean_out, uint32_t *durable_dirty_out) {
    uint32_t metadata_only = 0;
    uint32_t durable_clean = 0;
    uint32_t durable_dirty = 0;

    for (size_t i = 0; i < set->len; ++i) {
        if (!set->items[i].meta.has_data) {
            metadata_only++;
        } else if (set->items[i].meta.log_clean) {
            durable_clean++;
        } else {
            durable_dirty++;
        }
    }
    *metadata_only_out = metadata_only;
    *durable_clean_out = durable_clean;
    *durable_dirty_out = durable_dirty;
}

static int bloomd_handle_list(struct bloomd_filter_set *set, struct bloomd_response *resp) {
    int rc = bloomd_buffer_append_u32(&resp->body, (uint32_t)set->len);

    if (rc != 0) {
        return rc;
    }
    for (size_t i = 0; i < set->len; ++i) {
        uint16_t len = (uint16_t)strlen(set->items[i].meta.name);

        rc = bloomd_buffer_append_u16(&resp->body, len);
        if (rc != 0) {
            return rc;
        }
        rc = bloomd_buffer_append(&resp->body, set->items[i].meta.name, len);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

static int bloomd_handle_drop(struct bloomd_filter_set *set, struct bloomd_stats *stats,
                              const struct bloomd_request_view *req, struct bloomd_response *resp) {
    struct bloomd_name_request hdr;
    const char *name;
    struct bloomd_filter *filter;
    char errbuf[256];
    char rollback_errbuf[256];
    int pooled_fd = -1;
    uint64_t pooled_capacity = 0;
    uint32_t pooled_hashes = 0;
    uint32_t pooled_value_size = 0;
    int rc;

    if (req->header.body_len < sizeof(hdr)) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "short DROP body");
    }
    memcpy(&hdr, req->body, sizeof(hdr));
    if (sizeof(hdr) + hdr.name_len != req->header.body_len) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "malformed DROP body");
    }
    if (hdr.reserved0 != 0 || hdr.reserved1 != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                     "DROP reserved fields must be zero");
    }
    name = (const char *)(req->body + sizeof(hdr));
    if (bloomd_name_view_is_valid((const uint8_t *)name, hdr.name_len) != 0) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NAME, BLOOMD_ERR_PARSE, "invalid name");
    }
    filter = bloomd_filter_set_find_n(set, name, hdr.name_len);
    if (filter == NULL) {
        return bloomd_response_error(resp, BLOOMD_STATUS_NOT_FOUND, BLOOMD_ERR_NONE,
                                     "filter not found");
    }
    if (filter->meta.has_data) {
        rc = bloomd_bpf_unpin(filter->meta.pin_path, errbuf, sizeof(errbuf));
        if (rc != 0) {
            return bloomd_response_error(resp, BLOOMD_STATUS_BPF, BLOOMD_ERR_BPFFS, errbuf);
        }
    }
    rc = bloomd_meta_delete(filter->meta.meta_path);
    if (rc != 0) {
        if (filter->meta.has_data &&
            bloomd_bpf_pin_map(filter->map_fd, filter->meta.pin_path, rollback_errbuf,
                               sizeof(rollback_errbuf)) != 0) {
            bloomd_logf("error", "failed to restore pin path=%s after DROP rollback: %s",
                        filter->meta.pin_path, rollback_errbuf);
        }
        return bloomd_response_error(resp, BLOOMD_STATUS_IO, BLOOMD_ERR_METADATA,
                                     "failed to remove metadata");
    }
    if (!filter->meta.has_data) {
        pooled_fd = filter->map_fd;
        pooled_capacity = filter->meta.capacity;
        pooled_hashes = filter->meta.hashes;
        pooled_value_size = filter->meta.value_size;
        filter->map_fd = -1;
    }
    if (filter->meta.has_data) {
        rc = bloomd_log_delete(filter->meta.log_path);
        if (rc != 0) {
            bloomd_logf("warn", "failed to remove digest log path=%s: %s", filter->meta.log_path,
                        strerror(-rc));
        }
    }
    bloomd_filter_set_remove_n(set, name, hdr.name_len);
    if (pooled_fd >= 0) {
        bloomd_store_empty_map(pooled_fd, pooled_capacity, pooled_hashes, pooled_value_size);
    }
    stats->filters_dropped++;
    return 0;
}

static int bloomd_handle_stats(struct bloomd_filter_set *set, const struct bloomd_stats *stats,
                               struct bloomd_response *resp) {
    uint32_t metadata_only = 0;
    uint32_t durable_clean = 0;
    uint32_t durable_dirty = 0;
    int rc = 0;

    bloomd_count_filter_states(set, &metadata_only, &durable_clean, &durable_dirty);

    rc |= bloomd_buffer_append_u64(&resp->body, stats->requests);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->responses);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->errors);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->accepted_connections);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->filters_loaded);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->filters_created);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->filters_dropped);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->orphan_meta);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->orphan_pin);
    rc |= bloomd_buffer_append_u32(&resp->body, (uint32_t)set->len);
    rc |= bloomd_buffer_append_u32(&resp->body, metadata_only);
    rc |= bloomd_buffer_append_u32(&resp->body, durable_clean + durable_dirty);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->empty_pool_hits);
    rc |= bloomd_buffer_append_u64(&resp->body, stats->empty_pool_misses);
    return rc;
}

static int bloomd_dispatch(const struct bloomd_config *cfg, struct bloomd_filter_set *set,
                           struct bloomd_stats *stats, const struct bloomd_request_view *req,
                           struct bloomd_response *resp) {
    int rc;

    switch (req->header.opcode) {
    case BLOOMD_OP_PING:
        if (req->header.body_len != 0) {
            rc = bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                       "PING body must be empty");
            break;
        }
        rc = bloomd_handle_ping(resp);
        break;
    case BLOOMD_OP_CREATE:
        rc = bloomd_handle_create(cfg, set, stats, req, resp);
        break;
    case BLOOMD_OP_ADD:
        rc = bloomd_handle_add_check(set, NULL, req, resp, true, cfg->log_sync_mode);
        break;
    case BLOOMD_OP_CHECK:
        rc = bloomd_handle_add_check(set, NULL, req, resp, false, cfg->log_sync_mode);
        break;
    case BLOOMD_OP_MADD:
        rc = bloomd_handle_batch(set, req, resp, true, cfg->log_sync_mode);
        break;
    case BLOOMD_OP_MCHECK:
        rc = bloomd_handle_batch(set, req, resp, false, cfg->log_sync_mode);
        break;
    case BLOOMD_OP_INFO:
        rc = bloomd_handle_info(set, req, resp);
        break;
    case BLOOMD_OP_LIST:
        if (req->header.body_len != 0) {
            rc = bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                       "LIST body must be empty");
            break;
        }
        rc = bloomd_handle_list(set, resp);
        break;
    case BLOOMD_OP_DROP:
        rc = bloomd_handle_drop(set, stats, req, resp);
        break;
    case BLOOMD_OP_STATS:
        if (req->header.body_len != 0) {
            rc = bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                       "STATS body must be empty");
            break;
        }
        rc = bloomd_handle_stats(set, stats, resp);
        break;
    default:
        rc = bloomd_response_error(resp, BLOOMD_STATUS_BAD_REQUEST, BLOOMD_ERR_PARSE,
                                   "unknown opcode");
        break;
    }
    if (rc != 0 && resp->header.status == BLOOMD_STATUS_OK) {
        return bloomd_response_error(resp, BLOOMD_STATUS_INTERNAL, BLOOMD_ERR_NONE,
                                     "internal buffer failure");
    }
    return 0;
}

#define BLOOMD_MAX_CLIENTS 128U
#define BLOOMD_POLL_TIMEOUT_MS 250

enum bloomd_client_state {
    BLOOMD_CLIENT_EMPTY = 0,
    BLOOMD_CLIENT_READ_HEADER,
    BLOOMD_CLIENT_READ_BODY,
    BLOOMD_CLIENT_WRITE_RESPONSE
};

struct bloomd_client {
    int fd;
    enum bloomd_client_state state;
    uint64_t last_activity_ms;
    struct bloomd_frame_header req_header;
    size_t req_header_read;
    struct bloomd_buffer req_body;
    struct bloomd_request_view req;
    struct bloomd_response resp;
    struct bloomd_frame_header out_header;
    size_t write_offset;
};

static uint64_t bloomd_now_ms(void) {
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static int bloomd_set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -errno;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        return -errno;
    }
    return 0;
}

static int bloomd_header_is_valid(const struct bloomd_frame_header *hdr) {
    if (memcmp(hdr->magic, BLOOMD_PROTOCOL_MAGIC, 4) != 0) {
        return -EPROTO;
    }
    if (hdr->version != BLOOMD_PROTOCOL_VERSION) {
        return -EPROTO;
    }
    if (hdr->body_len > BLOOMD_MAX_FRAME_BODY) {
        return -E2BIG;
    }
    return 0;
}

static void bloomd_client_reset_request(struct bloomd_client *client) {
    memset(&client->req_header, 0, sizeof(client->req_header));
    memset(&client->req, 0, sizeof(client->req));
    client->req_header_read = 0;
    client->req_body.len = 0;
    client->write_offset = 0;
    client->state = BLOOMD_CLIENT_READ_HEADER;
}

static void bloomd_client_init(struct bloomd_client *client, int fd) {
    memset(client, 0, sizeof(*client));
    client->fd = fd;
    client->last_activity_ms = bloomd_now_ms();
    bloomd_buffer_init(&client->req_body);
    bloomd_response_init(&client->resp, 0, 0);
    bloomd_client_reset_request(client);
}

static void bloomd_client_close(struct bloomd_client *client) {
    if (client->fd >= 0) {
        close(client->fd);
    }
    bloomd_buffer_free(&client->req_body);
    bloomd_response_free(&client->resp);
    memset(client, 0, sizeof(*client));
    client->fd = -1;
    client->state = BLOOMD_CLIENT_EMPTY;
}

static int bloomd_client_prepare_write(struct bloomd_client *client) {
    client->out_header = client->resp.header;
    client->out_header.body_len = (uint32_t)client->resp.body.len;
    client->write_offset = 0;
    client->state = BLOOMD_CLIENT_WRITE_RESPONSE;
    return 0;
}

static int bloomd_client_read_some(struct bloomd_client *client, void *buf, size_t *offset,
                                   size_t want) {
    uint8_t *dst = buf;

    while (*offset < want) {
        ssize_t got = read(client->fd, dst + *offset, want - *offset);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -errno;
        }
        if (got == 0) {
            return -ECONNRESET;
        }
        *offset += (size_t)got;
        client->last_activity_ms = bloomd_now_ms();
    }
    return 1;
}

static int bloomd_client_drive_read(struct bloomd_client *client, const struct bloomd_config *cfg,
                                    struct bloomd_filter_set *set, struct bloomd_stats *stats) {
    int rc;

    if (client->state == BLOOMD_CLIENT_READ_HEADER) {
        rc = bloomd_client_read_some(client, &client->req_header, &client->req_header_read,
                                     sizeof(client->req_header));
        if (rc <= 0) {
            return rc;
        }
        rc = bloomd_header_is_valid(&client->req_header);
        if (rc != 0) {
            return rc;
        }
        client->req.header = client->req_header;
        if (client->req.header.body_len == 0) {
            client->req.body = NULL;
        } else {
            rc = bloomd_buffer_reserve(&client->req_body, client->req.header.body_len);
            if (rc != 0) {
                return rc;
            }
            client->req_body.len = 0;
            client->state = BLOOMD_CLIENT_READ_BODY;
            return 0;
        }
    }

    if (client->state == BLOOMD_CLIENT_READ_BODY) {
        size_t off = client->req_body.len;

        rc = bloomd_client_read_some(client, client->req_body.data, &off, client->req.header.body_len);
        client->req_body.len = off;
        if (rc <= 0) {
            return rc;
        }
        client->req.body = client->req_body.data;
    }

    stats->requests++;
    bloomd_response_reset(&client->resp, client->req.header.opcode, client->req.header.request_id);
    rc = bloomd_dispatch(cfg, set, stats, &client->req, &client->resp);
    if (rc != 0) {
        return rc;
    }
    if (client->resp.header.status != BLOOMD_STATUS_OK) {
        stats->errors++;
    }
    return bloomd_client_prepare_write(client);
}

static int bloomd_client_drive_write(struct bloomd_client *client, struct bloomd_stats *stats) {
    size_t total = sizeof(client->out_header) + client->resp.body.len;

    while (client->write_offset < total) {
        const uint8_t *base;
        size_t remain;
        ssize_t wrote;

        if (client->write_offset < sizeof(client->out_header)) {
            base = ((const uint8_t *)&client->out_header) + client->write_offset;
            remain = sizeof(client->out_header) - client->write_offset;
        } else {
            size_t body_off = client->write_offset - sizeof(client->out_header);

            base = client->resp.body.data + body_off;
            remain = client->resp.body.len - body_off;
        }

        wrote = write(client->fd, base, remain);
        if (wrote < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -errno;
        }
        if (wrote == 0) {
            return -EPIPE;
        }
        client->write_offset += (size_t)wrote;
        client->last_activity_ms = bloomd_now_ms();
    }

    stats->responses++;
    bloomd_client_reset_request(client);
    return 1;
}

static int bloomd_listen_socket(const char *socket_path, mode_t socket_mode) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    unlink(socket_path);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;

        close(fd);
        return -saved;
    }
    if (chmod(socket_path, socket_mode) != 0) {
        int saved = errno;

        close(fd);
        unlink(socket_path);
        return -saved;
    }
    if (listen(fd, 32) != 0) {
        int saved = errno;

        close(fd);
        unlink(socket_path);
        return -saved;
    }
    if (bloomd_set_nonblocking(fd) != 0) {
        int saved = errno;

        close(fd);
        unlink(socket_path);
        return -saved;
    }
    return fd;
}

static struct bloomd_client *bloomd_find_free_client(struct bloomd_client *clients, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (clients[i].state == BLOOMD_CLIENT_EMPTY) {
            return &clients[i];
        }
    }
    return NULL;
}

static void bloomd_accept_ready(int listen_fd, struct bloomd_client *clients, size_t len,
                                struct bloomd_stats *stats) {
    for (;;) {
        struct bloomd_client *slot;
        int client_fd;

        client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            bloomd_stderr("accept failed");
            return;
        }
        slot = bloomd_find_free_client(clients, len);
        if (slot == NULL) {
            bloomd_logf("warn", "dropping client because max_connections=%u reached",
                        BLOOMD_MAX_CLIENTS);
            close(client_fd);
            continue;
        }
        if (bloomd_set_nonblocking(client_fd) != 0) {
            close(client_fd);
            continue;
        }
        bloomd_client_init(slot, client_fd);
        stats->accepted_connections++;
    }
}

static void bloomd_close_timed_out_clients(struct bloomd_client *clients, size_t len) {
    uint64_t now = bloomd_now_ms();

    for (size_t i = 0; i < len; ++i) {
        if (clients[i].state == BLOOMD_CLIENT_EMPTY) {
            continue;
        }
        if (now - clients[i].last_activity_ms > BLOOMD_REQ_TIMEOUT_MS) {
            bloomd_logf("warn", "closing timed out client");
            bloomd_client_close(&clients[i]);
        }
    }
}

static int bloomd_parse_args(int argc, char **argv, struct bloomd_config *cfg) {
    bloomd_config_defaults(cfg);
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
            snprintf(cfg->socket_path, sizeof(cfg->socket_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--pin-root") == 0 && i + 1 < argc) {
            snprintf(cfg->pin_root, sizeof(cfg->pin_root), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--meta-root") == 0 && i + 1 < argc) {
            snprintf(cfg->meta_root, sizeof(cfg->meta_root), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--socket-mode") == 0 && i + 1 < argc) {
            if (bloomd_parse_octal_mode(argv[++i], &cfg->socket_mode) != 0) {
                fprintf(stderr, "invalid socket mode: %s\n", argv[i]);
                return -EINVAL;
            }
        } else if (strcmp(argv[i], "--log-sync-mode") == 0 && i + 1 < argc) {
            if (bloomd_parse_log_sync_mode(argv[++i], &cfg->log_sync_mode) != 0) {
                fprintf(stderr, "invalid log sync mode: %s\n", argv[i]);
                return -EINVAL;
            }
        } else if (strcmp(argv[i], "--foreground") == 0) {
            cfg->foreground = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: bloomd [--socket PATH] [--pin-root PATH] [--meta-root PATH] "
                   "[--socket-mode OCTAL] [--log-sync-mode periodic|always] [--foreground]\n");
            return 1;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("bloomd %s\n", BLOOMD_VERSION);
            return 1;
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            return -EINVAL;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    struct bloomd_config cfg;
    struct bloomd_filter_set filters;
    struct bloomd_stats stats;
    struct bloomd_client clients[BLOOMD_MAX_CLIENTS];
    struct bloomd_client *ready_clients[BLOOMD_MAX_CLIENTS + 1];
    struct pollfd pollfds[BLOOMD_MAX_CLIENTS + 1];
    char errbuf[256];
    int rc;
    int listen_fd = -1;

    rc = bloomd_parse_args(argc, argv, &cfg);
    if (rc > 0) {
        return 0;
    }
    if (rc != 0) {
        return 2;
    }

    memset(&stats, 0, sizeof(stats));
    bloomd_filter_set_init(&filters);
    for (size_t i = 0; i < BLOOMD_MAX_CLIENTS; ++i) {
        clients[i].fd = -1;
        clients[i].state = BLOOMD_CLIENT_EMPTY;
    }

    rc = bloomd_prepare_roots(&cfg, errbuf, sizeof(errbuf));
    if (rc != 0) {
        bloomd_stderr(errbuf);
        return 1;
    }
    rc = bloomd_bpf_probe_support(errbuf, sizeof(errbuf));
    if (rc != 0) {
        bloomd_stderr(errbuf);
        return 1;
    }
    bloomd_logf("info", "kernel Bloom map probe succeeded");
    rc = bloomd_load_metadata_dir(&cfg, &filters, &stats, errbuf, sizeof(errbuf));
    if (rc != 0) {
        bloomd_stderr(errbuf);
        bloomd_filter_set_free(&filters);
        bloomd_close_empty_pool();
        return 1;
    }
    rc = bloomd_cleanup_orphan_pins(&cfg, &filters, &stats);
    if (rc != 0) {
        bloomd_stderr("failed to reconcile pinned maps");
        bloomd_filter_set_free(&filters);
        bloomd_close_empty_pool();
        return 1;
    }
    {
        uint32_t metadata_only = 0;
        uint32_t durable_clean = 0;
        uint32_t durable_dirty = 0;

        bloomd_count_filter_states(&filters, &metadata_only, &durable_clean, &durable_dirty);
        bloomd_logf("info",
                    "startup reconciliation complete loaded=%llu metadata_only=%u durable_clean=%u "
                    "durable_dirty=%u orphan_meta=%llu orphan_pin=%llu",
                    (unsigned long long)stats.filters_loaded, metadata_only, durable_clean,
                    durable_dirty, (unsigned long long)stats.orphan_meta,
                    (unsigned long long)stats.orphan_pin);
    }

    rc = bloomd_install_signal_handlers();
    if (rc != 0) {
        bloomd_stderr("failed to install signal handlers");
        bloomd_filter_set_free(&filters);
        bloomd_close_empty_pool();
        return 1;
    }

    listen_fd = bloomd_listen_socket(cfg.socket_path, cfg.socket_mode);
    if (listen_fd < 0) {
        bloomd_stderr("failed to create unix socket");
        bloomd_filter_set_free(&filters);
        bloomd_close_empty_pool();
        return 1;
    }
    bloomd_logf("info", "listening on unix socket path=%s mode=%03o", cfg.socket_path,
                (unsigned)cfg.socket_mode);
    while (!bloomd_stop) {
        nfds_t nfds = 1;

        pollfds[0].fd = listen_fd;
        pollfds[0].events = POLLIN;
        pollfds[0].revents = 0;
        ready_clients[0] = NULL;

        for (size_t i = 0; i < BLOOMD_MAX_CLIENTS; ++i) {
            if (clients[i].state == BLOOMD_CLIENT_EMPTY) {
                continue;
            }
            pollfds[nfds].fd = clients[i].fd;
            pollfds[nfds].events =
                clients[i].state == BLOOMD_CLIENT_WRITE_RESPONSE ? POLLOUT : POLLIN;
            pollfds[nfds].revents = 0;
            ready_clients[nfds] = &clients[i];
            nfds++;
        }

        rc = poll(pollfds, nfds, BLOOMD_POLL_TIMEOUT_MS);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            bloomd_stderr("poll failed");
            break;
        }
        if (pollfds[0].revents & POLLIN) {
            bloomd_accept_ready(listen_fd, clients, BLOOMD_MAX_CLIENTS, &stats);
        }

        for (nfds_t i = 1; i < nfds; ++i) {
            struct bloomd_client *client = ready_clients[i];
            int io_rc = 0;

            if (client == NULL || client->state == BLOOMD_CLIENT_EMPTY) {
                continue;
            }
            if (pollfds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                bloomd_client_close(client);
                continue;
            }
            if ((client->state == BLOOMD_CLIENT_WRITE_RESPONSE &&
                 (pollfds[i].revents & POLLOUT)) ||
                (client->state != BLOOMD_CLIENT_WRITE_RESPONSE &&
                 (pollfds[i].revents & POLLIN))) {
                if (client->state == BLOOMD_CLIENT_WRITE_RESPONSE) {
                    io_rc = bloomd_client_drive_write(client, &stats);
                } else {
                    io_rc = bloomd_client_drive_read(client, &cfg, &filters, &stats);
                    if (io_rc > 0 && client->state == BLOOMD_CLIENT_WRITE_RESPONSE) {
                        io_rc = bloomd_client_drive_write(client, &stats);
                    }
                }
            }
            if (io_rc < 0) {
                if (io_rc != -ECONNRESET && io_rc != -EPIPE) {
                    bloomd_logf("warn", "closing client fd=%d state=%d rc=%d err=%s", client->fd,
                                (int)client->state, io_rc, strerror(-io_rc));
                }
                bloomd_client_close(client);
            }
        }

        bloomd_close_timed_out_clients(clients, BLOOMD_MAX_CLIENTS);
        bloomd_sync_dirty_logs(&filters, bloomd_now_ms(), false);
    }

    bloomd_sync_dirty_logs(&filters, bloomd_now_ms(), true);
    for (size_t i = 0; i < BLOOMD_MAX_CLIENTS; ++i) {
        if (clients[i].state != BLOOMD_CLIENT_EMPTY) {
            bloomd_client_close(&clients[i]);
        }
    }
    close(listen_fd);
    unlink(cfg.socket_path);
    bloomd_logf("info", "shutdown complete");
    bloomd_filter_set_free(&filters);
    bloomd_close_empty_pool();
    return 0;
}
