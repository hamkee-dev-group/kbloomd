#define main bloomd_daemon_main
#include "../src/daemon.c"
#undef main

#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define MOCK_MAX_MAPS 8U
#define MOCK_MAX_PINS 8U
#define MOCK_MAX_DIGESTS 64U

struct mock_map {
    int ref_fd;
    ino_t ino;
    uint32_t max_entries;
    uint32_t value_size;
    uint64_t map_extra;
    uint8_t digests[MOCK_MAX_DIGESTS][BLOOMD_DIGEST_SIZE];
    size_t digest_count;
};

struct mock_pin {
    char path[PATH_MAX];
    size_t map_index;
};

static struct mock_map mock_maps[MOCK_MAX_MAPS];
static size_t mock_map_count;
static struct mock_pin mock_pins[MOCK_MAX_PINS];
static size_t mock_pin_count;

static void mock_reset(void) {
    for (size_t i = 0; i < mock_map_count; ++i) {
        close(mock_maps[i].ref_fd);
    }
    memset(mock_maps, 0, sizeof(mock_maps));
    memset(mock_pins, 0, sizeof(mock_pins));
    mock_map_count = 0;
    mock_pin_count = 0;
}

/* Each mock map is backed by a memfd the mock keeps open. Its inode identifies
 * the map behind every dup'd fd handed to the daemon, even after the daemon
 * closes those fds and the numbers are reused. */
static int mock_map_create(uint32_t max_entries, uint64_t map_extra, uint32_t value_size) {
    struct mock_map *map;
    struct stat st;
    int fd;

    if (mock_map_count == MOCK_MAX_MAPS) {
        return -1;
    }
    fd = memfd_create("bloomd-mock-map", MFD_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }
    map = &mock_maps[mock_map_count];
    memset(map, 0, sizeof(*map));
    map->ref_fd = fd;
    map->ino = st.st_ino;
    map->max_entries = max_entries;
    map->map_extra = map_extra;
    map->value_size = value_size;
    return (int)mock_map_count++;
}

static int mock_map_handle(int index) {
    return dup(mock_maps[index].ref_fd);
}

static int mock_map_by_fd(int fd) {
    struct stat st;

    if (fd < 0 || fstat(fd, &st) != 0) {
        return -1;
    }
    for (size_t i = 0; i < mock_map_count; ++i) {
        if (mock_maps[i].ino == st.st_ino) {
            return (int)i;
        }
    }
    return -1;
}

static bool mock_map_has(int index, const uint8_t digest[BLOOMD_DIGEST_SIZE]) {
    const struct mock_map *map = &mock_maps[index];

    for (size_t i = 0; i < map->digest_count; ++i) {
        if (memcmp(map->digests[i], digest, BLOOMD_DIGEST_SIZE) == 0) {
            return true;
        }
    }
    return false;
}

static int mock_map_add(int index, const uint8_t digest[BLOOMD_DIGEST_SIZE]) {
    struct mock_map *map = &mock_maps[index];

    if (mock_map_has(index, digest)) {
        return 0;
    }
    if (map->digest_count == MOCK_MAX_DIGESTS) {
        return -1;
    }
    memcpy(map->digests[map->digest_count++], digest, BLOOMD_DIGEST_SIZE);
    return 0;
}

static int mock_pin_find(const char *path) {
    for (size_t i = 0; i < mock_pin_count; ++i) {
        if (strcmp(mock_pins[i].path, path) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static int mock_pin_add(const char *path, int map_index) {
    if (mock_pin_find(path) >= 0) {
        return -EEXIST;
    }
    if (mock_pin_count == MOCK_MAX_PINS) {
        return -ENOSPC;
    }
    snprintf(mock_pins[mock_pin_count].path, sizeof(mock_pins[mock_pin_count].path), "%s", path);
    mock_pins[mock_pin_count].map_index = (size_t)map_index;
    mock_pin_count++;
    return 0;
}

static void mock_pin_remove(const char *path) {
    int index = mock_pin_find(path);

    if (index < 0) {
        return;
    }
    memmove(&mock_pins[index], &mock_pins[index + 1],
            (mock_pin_count - (size_t)index - 1) * sizeof(mock_pins[0]));
    mock_pin_count--;
}

static long mock_bpf_syscall(int cmd, void *attr_void, unsigned int size) {
    union bpf_attr *attr = attr_void;
    int index;
    int rc;

    (void)size;
    switch (cmd) {
    case BPF_MAP_CREATE:
        if (attr->map_type != BPF_MAP_TYPE_BLOOM_FILTER) {
            errno = EINVAL;
            return -1;
        }
        index = mock_map_create(attr->max_entries, attr->map_extra, attr->value_size);
        if (index < 0) {
            errno = ENOMEM;
            return -1;
        }
        return mock_map_handle(index);
    case BPF_OBJ_GET:
        index = mock_pin_find((const char *)(uintptr_t)attr->pathname);
        if (index < 0) {
            errno = ENOENT;
            return -1;
        }
        return mock_map_handle((int)mock_pins[index].map_index);
    case BPF_OBJ_PIN:
        index = mock_map_by_fd((int)attr->bpf_fd);
        if (index < 0) {
            errno = EBADF;
            return -1;
        }
        rc = mock_pin_add((const char *)(uintptr_t)attr->pathname, index);
        if (rc != 0) {
            errno = -rc;
            return -1;
        }
        return 0;
    case BPF_MAP_UPDATE_ELEM:
        index = mock_map_by_fd((int)attr->map_fd);
        if (index < 0) {
            errno = EBADF;
            return -1;
        }
        if (mock_map_add(index, (const uint8_t *)(uintptr_t)attr->value) != 0) {
            errno = E2BIG;
            return -1;
        }
        return 0;
    case BPF_MAP_LOOKUP_ELEM:
        index = mock_map_by_fd((int)attr->map_fd);
        if (index < 0) {
            errno = EBADF;
            return -1;
        }
        if (!mock_map_has(index, (const uint8_t *)(uintptr_t)attr->value)) {
            errno = ENOENT;
            return -1;
        }
        return 0;
    case BPF_OBJ_GET_INFO_BY_FD: {
        struct bpf_map_info info;

        index = mock_map_by_fd((int)attr->info.bpf_fd);
        if (index < 0) {
            errno = EBADF;
            return -1;
        }
        memset(&info, 0, sizeof(info));
        info.type = BPF_MAP_TYPE_BLOOM_FILTER;
        info.key_size = 0;
        info.value_size = mock_maps[index].value_size;
        info.max_entries = mock_maps[index].max_entries;
        info.map_extra = mock_maps[index].map_extra;
        memcpy((void *)(uintptr_t)attr->info.info, &info,
               attr->info.info_len < sizeof(info) ? attr->info.info_len : sizeof(info));
        return 0;
    }
    default:
        errno = EINVAL;
        return -1;
    }
}

struct test_env {
    char root[64];
    struct bloomd_config cfg;
};

static int env_setup(struct test_env *env) {
    snprintf(env->root, sizeof(env->root), "/tmp/bloomd-recovery-XXXXXX");
    if (mkdtemp(env->root) == NULL) {
        perror("mkdtemp");
        return -1;
    }
    bloomd_config_defaults(&env->cfg);
    snprintf(env->cfg.meta_root, sizeof(env->cfg.meta_root), "%s/meta", env->root);
    snprintf(env->cfg.pin_root, sizeof(env->cfg.pin_root), "%s/pin", env->root);
    env->cfg.log_sync_mode = BLOOMD_LOG_SYNC_PERIODIC;
    if (bloomd_ensure_dir(env->cfg.meta_root, 0755, false) != 0 ||
        bloomd_ensure_dir(env->cfg.pin_root, 0755, false) != 0) {
        fprintf(stderr, "FAIL: could not create temp roots under %s\n", env->root);
        return -1;
    }
    mock_reset();
    bloomd_bpf_set_mock_syscall(mock_bpf_syscall);
    return 0;
}

static void env_remove_dir(const char *path) {
    char **names = NULL;
    size_t count = 0;

    if (bloomd_list_dir(path, &names, &count) == 0) {
        for (size_t i = 0; i < count; ++i) {
            char child[PATH_MAX];

            if (snprintf(child, sizeof(child), "%s/%s", path, names[i]) < (int)sizeof(child)) {
                unlink(child);
            }
        }
        bloomd_free_name_list(names, count);
    }
    rmdir(path);
}

static void env_teardown(struct test_env *env) {
    bloomd_bpf_reset_mock_syscall();
    mock_reset();
    env_remove_dir(env->cfg.meta_root);
    env_remove_dir(env->cfg.pin_root);
    rmdir(env->root);
}

/* Lay down a durable filter whose pinned map already holds 'old'. With
 * history_complete the digest log records 'old' and log_clean=1; otherwise the
 * log is empty and log_clean=0, i.e. the map holds data the log never saw. */
static int seed_filter(const struct bloomd_config *cfg, const char *name, bool history_complete) {
    struct bloomd_filter_meta meta;
    uint8_t digest[BLOOMD_DIGEST_SIZE];
    int index;
    int rc;

    memset(&meta, 0, sizeof(meta));
    snprintf(meta.name, sizeof(meta.name), "%s", name);
    snprintf(meta.backend, sizeof(meta.backend), "%s", BLOOMD_BACKEND_NAME);
    snprintf(meta.digest, sizeof(meta.digest), "%s", BLOOMD_DIGEST_NAME);
    meta.capacity = 1024;
    meta.error_rate = 0.01;
    meta.hashes = 3;
    meta.value_size = BLOOMD_DIGEST_SIZE;
    meta.metadata_version = BLOOMD_METADATA_VERSION;
    meta.has_data = true;
    meta.log_clean = history_complete;
    rc = bloomd_assign_filter_paths(cfg, &meta);
    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_assign_filter_paths: %s\n", strerror(-rc));
        return -1;
    }
    rc = bloomd_meta_write_atomic(&meta);
    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_meta_write_atomic: %s\n", strerror(-rc));
        return -1;
    }
    rc = bloomd_log_reset(meta.log_path);
    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_log_reset: %s\n", strerror(-rc));
        return -1;
    }
    bloomd_digest_payload("old", 3, digest);
    if (history_complete) {
        int fd = bloomd_log_open_append(meta.log_path);

        if (fd < 0 || bloomd_log_append_fd(fd, digest) != 0) {
            fprintf(stderr, "FAIL: could not seed digest log %s\n", meta.log_path);
            return -1;
        }
        bloomd_log_close(&fd, true);
    }
    index = mock_map_create((uint32_t)meta.capacity, meta.hashes, meta.value_size);
    if (index < 0 || mock_map_add(index, digest) != 0 || mock_pin_add(meta.pin_path, index) != 0) {
        fprintf(stderr, "FAIL: could not seed mock pinned map %s\n", meta.pin_path);
        return -1;
    }
    return 0;
}

static int response_failed(const struct bloomd_response *resp, int rc, const char *op,
                           const char *item) {
    if (rc == 0 && resp->header.status == BLOOMD_STATUS_OK) {
        return 0;
    }
    if (resp->body.len >= 8) {
        uint32_t msg_len = bloomd_load_u32(resp->body.data + 4);

        fprintf(stderr, "FAIL: %s %s: rc=%d status=%u message=%.*s\n", op, item, rc,
                resp->header.status, (int)msg_len, (const char *)resp->body.data + 8);
    } else {
        fprintf(stderr, "FAIL: %s %s: rc=%d status=%u\n", op, item, rc, resp->header.status);
    }
    return -1;
}

/* Returns 1 if present after the op, 0 if absent, -1 on error. */
static int do_add_check(struct bloomd_filter_set *set, const struct bloomd_config *cfg,
                        const char *name, const char *item, bool is_add) {
    struct bloomd_payload_request hdr;
    struct bloomd_request_view req;
    struct bloomd_response resp;
    uint8_t body[256];
    size_t name_len = strlen(name);
    size_t item_len = strlen(item);
    int rc;

    memset(&hdr, 0, sizeof(hdr));
    hdr.name_len = (uint16_t)name_len;
    hdr.payload_len = (uint32_t)item_len;
    memcpy(body, &hdr, sizeof(hdr));
    memcpy(body + sizeof(hdr), name, name_len);
    memcpy(body + sizeof(hdr) + name_len, item, item_len);
    memset(&req, 0, sizeof(req));
    req.header.opcode = is_add ? BLOOMD_OP_ADD : BLOOMD_OP_CHECK;
    req.header.body_len = (uint32_t)(sizeof(hdr) + name_len + item_len);
    req.body = body;
    bloomd_response_init(&resp, req.header.opcode, 1);
    rc = bloomd_handle_add_check(set, NULL, &req, &resp, is_add, cfg->log_sync_mode);
    if (response_failed(&resp, rc, is_add ? "ADD" : "CHECK", item) != 0) {
        rc = -1;
    } else {
        rc = resp.body.len == 1 ? (resp.body.data[0] != 0) : -1;
    }
    bloomd_response_free(&resp);
    return rc;
}

static int do_madd(struct bloomd_filter_set *set, const struct bloomd_config *cfg, const char *name,
                   const char *const *items, uint16_t count) {
    struct bloomd_batch_request hdr;
    struct bloomd_request_view req;
    struct bloomd_response resp;
    uint8_t body[512];
    size_t name_len = strlen(name);
    size_t off;
    int rc;

    memset(&hdr, 0, sizeof(hdr));
    hdr.name_len = (uint16_t)name_len;
    hdr.item_count = count;
    memcpy(body, &hdr, sizeof(hdr));
    off = sizeof(hdr);
    memcpy(body + off, name, name_len);
    off += name_len;
    for (uint16_t i = 0; i < count; ++i) {
        uint32_t len = (uint32_t)strlen(items[i]);

        body[off++] = (uint8_t)(len & 0xffU);
        body[off++] = (uint8_t)((len >> 8) & 0xffU);
        body[off++] = (uint8_t)((len >> 16) & 0xffU);
        body[off++] = (uint8_t)((len >> 24) & 0xffU);
        memcpy(body + off, items[i], len);
        off += len;
    }
    memset(&req, 0, sizeof(req));
    req.header.opcode = BLOOMD_OP_MADD;
    req.header.body_len = (uint32_t)off;
    req.body = body;
    bloomd_response_init(&resp, BLOOMD_OP_MADD, 1);
    rc = bloomd_handle_batch(set, &req, &resp, true, cfg->log_sync_mode);
    rc = response_failed(&resp, rc, "MADD", items[0]);
    bloomd_response_free(&resp);
    return rc;
}

static int disk_log_clean(const char *meta_path, bool *log_clean_out) {
    struct bloomd_filter_meta meta;
    int rc = bloomd_meta_read_file(meta_path, &meta);

    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_meta_read_file(%s): %s\n", meta_path, strerror(-rc));
        return -1;
    }
    *log_clean_out = meta.log_clean;
    return 0;
}

static long log_record_count(const char *log_path) {
    struct stat st;

    if (stat(log_path, &st) != 0) {
        return -1;
    }
    return (long)(st.st_size / BLOOMD_DIGEST_SIZE);
}

static int load_filters(const struct bloomd_config *cfg, struct bloomd_filter_set *set,
                        char *errbuf, size_t errcap) {
    struct bloomd_stats stats;

    bloomd_filter_set_init(set);
    memset(&stats, 0, sizeof(stats));
    return bloomd_load_metadata_dir(cfg, set, &stats, errbuf, errcap);
}

static void shutdown_filters(struct bloomd_filter_set *set) {
    bloomd_sync_dirty_logs(set, bloomd_now_ms(), true);
    bloomd_filter_set_free(set);
}

static int run_inherited_dirty_case(bool batch_first_write) {
    const char *label = batch_first_write ? "MADD" : "ADD";
    static const char *const batch_items[] = {"new", "new2"};
    struct test_env env;
    struct bloomd_filter_set set;
    struct bloomd_filter *filter;
    char errbuf[256];
    char meta_path[PATH_MAX];
    char log_path[PATH_MAX];
    char pin_path[PATH_MAX];
    bool log_clean;
    long records;
    int rc;
    int result = 1;

    if (env_setup(&env) != 0) {
        return 1;
    }
    bloomd_filter_set_init(&set);
    if (seed_filter(&env.cfg, "users", false) != 0) {
        goto out;
    }
    bloomd_build_meta_path(env.cfg.meta_root, "users", meta_path, sizeof(meta_path));
    bloomd_build_log_path(env.cfg.meta_root, "users", log_path, sizeof(log_path));
    bloomd_build_pin_path(env.cfg.pin_root, "users", pin_path, sizeof(pin_path));

    rc = load_filters(&env.cfg, &set, errbuf, sizeof(errbuf));
    if (rc != 0) {
        fprintf(stderr, "FAIL [%s]: initial load: %s (%s)\n", label, errbuf, strerror(-rc));
        goto out;
    }
    filter = bloomd_filter_set_find(&set, "users");
    if (filter == NULL || filter->meta.log_clean) {
        fprintf(stderr, "FAIL [%s]: filter should load with log_clean=0\n", label);
        goto out;
    }

    if (batch_first_write) {
        rc = do_madd(&set, &env.cfg, "users", batch_items, 2);
    } else {
        rc = do_add_check(&set, &env.cfg, "users", "new", true) < 0 ? -1 : 0;
    }
    if (rc != 0) {
        goto out;
    }
    bloomd_sync_dirty_logs(&set, bloomd_now_ms(), true);

    records = log_record_count(log_path);
    if (records != (batch_first_write ? 2 : 1)) {
        fprintf(stderr, "FAIL [%s]: expected %d log records after sync, got %ld\n", label,
                batch_first_write ? 2 : 1, records);
        goto out;
    }
    if (filter->meta.log_clean) {
        fprintf(stderr, "FAIL [%s]: in-memory log_clean promoted to 1 after syncing later writes\n",
                label);
        goto out;
    }
    if (disk_log_clean(meta_path, &log_clean) != 0) {
        goto out;
    }
    if (log_clean) {
        fprintf(stderr, "FAIL [%s]: on-disk log_clean promoted to 1 after syncing later writes\n",
                label);
        goto out;
    }

    if (do_add_check(&set, &env.cfg, "users", "later", true) < 0) {
        goto out;
    }
    shutdown_filters(&set);
    rc = load_filters(&env.cfg, &set, errbuf, sizeof(errbuf));
    if (rc != 0) {
        fprintf(stderr, "FAIL [%s]: reload with pin present: %s (%s)\n", label, errbuf,
                strerror(-rc));
        goto out;
    }
    if (do_add_check(&set, &env.cfg, "users", "later2", true) < 0) {
        goto out;
    }
    shutdown_filters(&set);

    mock_pin_remove(pin_path);
    rc = load_filters(&env.cfg, &set, errbuf, sizeof(errbuf));
    if (rc != -EUCLEAN) {
        fprintf(stderr, "FAIL [%s]: load after pin loss expected -EUCLEAN, got %d (%s)\n", label, rc,
                rc == 0 ? "rebuilt from incomplete log" : errbuf);
        if (rc == 0) {
            fprintf(stderr, "FAIL [%s]: rebuilt map has old=%d new=%d\n", label,
                    do_add_check(&set, &env.cfg, "users", "old", false),
                    do_add_check(&set, &env.cfg, "users", "new", false));
        }
        goto out;
    }
    if (set.len != 0) {
        fprintf(stderr, "FAIL [%s]: refused rebuild still loaded %zu filters\n", label, set.len);
        goto out;
    }
    printf("PASS: inherited dirty log stays unsafe after %s + sync and refuses rebuild on pin loss\n",
           label);
    result = 0;
out:
    bloomd_filter_set_free(&set);
    env_teardown(&env);
    return result;
}

static int run_pending_writes_case(void) {
    struct test_env env;
    struct bloomd_filter_set set;
    struct bloomd_filter *filter;
    char errbuf[256];
    char meta_path[PATH_MAX];
    char pin_path[PATH_MAX];
    bool log_clean;
    int rc;
    int result = 1;

    if (env_setup(&env) != 0) {
        return 1;
    }
    bloomd_filter_set_init(&set);
    if (seed_filter(&env.cfg, "users", true) != 0) {
        goto out;
    }
    bloomd_build_meta_path(env.cfg.meta_root, "users", meta_path, sizeof(meta_path));
    bloomd_build_pin_path(env.cfg.pin_root, "users", pin_path, sizeof(pin_path));

    rc = load_filters(&env.cfg, &set, errbuf, sizeof(errbuf));
    if (rc != 0) {
        fprintf(stderr, "FAIL [pending]: initial load: %s (%s)\n", errbuf, strerror(-rc));
        goto out;
    }
    filter = bloomd_filter_set_find(&set, "users");
    if (filter == NULL || !filter->meta.log_clean) {
        fprintf(stderr, "FAIL [pending]: filter should load with log_clean=1\n");
        goto out;
    }
    if (do_add_check(&set, &env.cfg, "users", "new", true) < 0) {
        goto out;
    }
    if (disk_log_clean(meta_path, &log_clean) != 0) {
        goto out;
    }
    if (log_clean || filter->meta.log_clean) {
        fprintf(stderr, "FAIL [pending]: unsynced periodic write should mark log_clean=0\n");
        goto out;
    }
    bloomd_sync_dirty_logs(&set, bloomd_now_ms(), true);
    if (disk_log_clean(meta_path, &log_clean) != 0) {
        goto out;
    }
    if (!log_clean || !filter->meta.log_clean) {
        fprintf(stderr, "FAIL [pending]: synced pending write should restore log_clean=1\n");
        goto out;
    }
    shutdown_filters(&set);

    mock_pin_remove(pin_path);
    rc = load_filters(&env.cfg, &set, errbuf, sizeof(errbuf));
    if (rc != 0 || set.len != 1) {
        fprintf(stderr, "FAIL [pending]: rebuild after pin loss rc=%d loaded=%zu (%s)\n", rc, set.len,
                errbuf);
        goto out;
    }
    if (do_add_check(&set, &env.cfg, "users", "old", false) != 1 ||
        do_add_check(&set, &env.cfg, "users", "new", false) != 1) {
        fprintf(stderr, "FAIL [pending]: rebuilt map should contain old and new\n");
        goto out;
    }
    printf("PASS: synced pending writes restore log_clean=1 and rebuild after pin loss\n");
    result = 0;
out:
    bloomd_filter_set_free(&set);
    env_teardown(&env);
    return result;
}

int main(void) {
    if (run_inherited_dirty_case(false) != 0) {
        return 1;
    }
    if (run_inherited_dirty_case(true) != 0) {
        return 1;
    }
    if (run_pending_writes_case() != 0) {
        return 1;
    }
    return 0;
}
