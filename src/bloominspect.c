#include "bloomd.h"

#include <errno.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct inspect_stats {
    uint32_t ok;
    uint32_t invalid_meta;
    uint32_t missing_log;
    uint32_t bad_log;
    uint32_t rebuildable;
    uint32_t unsafe_rebuild;
    uint32_t stale_meta;
    uint32_t bad_pin;
    uint32_t orphan_pin;
};

static int inspect_log_noop(const uint8_t digest[BLOOMD_DIGEST_SIZE], void *ctx) {
    (void)digest;
    (void)ctx;
    return 0;
}

static bool inspect_has_suffix(const char *name, const char *suffix) {
    size_t name_len = strlen(name);
    size_t suffix_len = strlen(suffix);

    return name_len >= suffix_len && strcmp(name + name_len - suffix_len, suffix) == 0;
}

static bool inspect_path_under_root(const char *path, const char *root) {
    size_t root_len = strlen(root);

    return strncmp(path, root, root_len) == 0 &&
           (path[root_len] == '/' || path[root_len] == '\0');
}

static bool inspect_path_has_name(const char *path, const char *name) {
    const char *slash = strrchr(path, '/');

    return slash != NULL && strcmp(slash + 1, name) == 0;
}

static int inspect_entry_name(const char *entry, char out[BLOOMD_MAX_NAME_LEN + 1]) {
    size_t len = strlen(entry);

    if (!inspect_has_suffix(entry, ".meta")) {
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

static bool inspect_contains(char **names, size_t count, const char *name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcmp(names[i], name) == 0) {
            return true;
        }
    }
    return false;
}

static int inspect_add_name(char ***names, size_t *count, size_t *cap, const char *name) {
    char **next;
    char *copy;

    if (*count == *cap) {
        size_t new_cap = *cap == 0 ? 8U : *cap * 2U;

        next = realloc(*names, new_cap * sizeof(*next));
        if (next == NULL) {
            return -ENOMEM;
        }
        *names = next;
        *cap = new_cap;
    }
    copy = strdup(name);
    if (copy == NULL) {
        return -ENOMEM;
    }
    (*names)[(*count)++] = copy;
    return 0;
}

static bool inspect_validate_pin_matches_meta(const struct bloomd_filter_meta *meta, int fd) {
    struct bloomd_bpf_map_info info;

    if (fd < 0 || bloomd_bpf_get_map_info(fd, &info, NULL, 0) != 0) {
        return false;
    }
    return info.type == BPF_MAP_TYPE_BLOOM_FILTER && info.key_size == 0 &&
           info.value_size == meta->value_size && info.max_entries == meta->capacity &&
           (info.map_extra & 0x0fU) == meta->hashes;
}

static void inspect_usage(void) {
    fprintf(stderr,
            "usage: bloominspect [--pin-root PATH] [--meta-root PATH] [--strict]\n");
}

int main(int argc, char **argv) {
    char pin_root[PATH_MAX];
    char meta_root[PATH_MAX];
    bool strict = false;
    char **meta_entries = NULL;
    char **pin_entries = NULL;
    char **loaded_names = NULL;
    size_t meta_count = 0;
    size_t pin_count = 0;
    size_t loaded_count = 0;
    size_t loaded_cap = 0;
    struct inspect_stats stats = {0};
    int rc;

    snprintf(pin_root, sizeof(pin_root), "%s", BLOOMD_DEFAULT_PIN_ROOT);
    snprintf(meta_root, sizeof(meta_root), "%s", BLOOMD_DEFAULT_META_ROOT);

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--pin-root") == 0 && i + 1 < argc) {
            snprintf(pin_root, sizeof(pin_root), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--meta-root") == 0 && i + 1 < argc) {
            snprintf(meta_root, sizeof(meta_root), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--strict") == 0) {
            strict = true;
        } else if (strcmp(argv[i], "--version") == 0) {
            printf("bloominspect %s\n", BLOOMD_VERSION);
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            inspect_usage();
            return 0;
        } else {
            inspect_usage();
            return 2;
        }
    }

    rc = bloomd_list_dir(meta_root, &meta_entries, &meta_count);
    if (rc != 0 && rc != -ENOENT) {
        fprintf(stderr, "bloominspect: failed to list metadata directory: %s\n", strerror(-rc));
        return 1;
    }
    rc = bloomd_list_dir(pin_root, &pin_entries, &pin_count);
    if (rc != 0 && rc != -ENOENT) {
        fprintf(stderr, "bloominspect: failed to list pin directory: %s\n", strerror(-rc));
        bloomd_free_name_list(meta_entries, meta_count);
        return 1;
    }

    printf("bloominspect: meta_root=%s pin_root=%s\n", meta_root, pin_root);
    for (size_t i = 0; i < meta_count; ++i) {
        struct bloomd_filter_meta meta;
        char path[PATH_MAX];
        char log_path[PATH_MAX];
        char entry_name[BLOOMD_MAX_NAME_LEN + 1];
        uint64_t replay_count = 0;
        int log_rc;
        int fd;

        if (!inspect_has_suffix(meta_entries[i], ".meta")) {
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", meta_root, meta_entries[i]) >= (int)sizeof(path)) {
            printf("invalid_meta path_too_long=%s/%s\n", meta_root, meta_entries[i]);
            stats.invalid_meta++;
            continue;
        }
        if (inspect_entry_name(meta_entries[i], entry_name) != 0 ||
            bloomd_meta_read_file(path, &meta) != 0 ||
            strcmp(entry_name, meta.name) != 0 ||
            !inspect_path_under_root(meta.pin_path, pin_root) ||
            !inspect_path_has_name(meta.pin_path, meta.name)) {
            printf("invalid_meta path=%s\n", path);
            stats.invalid_meta++;
            continue;
        }
        if (bloomd_build_log_path(meta_root, meta.name, log_path, sizeof(log_path)) != 0) {
            printf("invalid_meta path=%s\n", path);
            stats.invalid_meta++;
            continue;
        }
        log_rc = bloomd_log_replay_readonly(log_path, inspect_log_noop, NULL, &replay_count);
        fd = bloomd_bpf_open_pinned(meta.pin_path);
        if (!meta.has_data) {
            if (fd >= 0) {
                if (!inspect_validate_pin_matches_meta(&meta, fd)) {
                    bloomd_bpf_close(&fd);
                    printf("bad_pin name=%s path=%s pin=%s error=metadata_mismatch\n", meta.name, path,
                           meta.pin_path);
                    stats.bad_pin++;
                } else {
                    bloomd_bpf_close(&fd);
                    printf("ok name=%s meta=%s pin=%s log=%s replay_count=0 empty=1 log_clean=%u\n",
                           meta.name, path, meta.pin_path, log_path, meta.log_clean ? 1U : 0U);
                    stats.ok++;
                }
            } else if (fd == -ENOENT && log_rc == -ENOENT) {
                printf("ok name=%s meta=%s pin=%s log=%s replay_count=0 empty=1 log_clean=%u\n",
                       meta.name, path, meta.pin_path, log_path, meta.log_clean ? 1U : 0U);
                stats.ok++;
            } else if (fd == -ENOENT && log_rc == 0) {
                if (meta.log_clean) {
                    printf("rebuildable name=%s meta=%s pin=%s log=%s replay_count=%llu log_clean=1\n",
                           meta.name, path, meta.pin_path, log_path, (unsigned long long)replay_count);
                    stats.rebuildable++;
                } else {
                    printf("unsafe_rebuild name=%s meta=%s pin=%s log=%s replay_count=%llu log_clean=0\n",
                           meta.name, path, meta.pin_path, log_path, (unsigned long long)replay_count);
                    stats.unsafe_rebuild++;
                }
            } else if (log_rc != 0 && log_rc != -ENOENT) {
                printf("bad_log name=%s meta=%s pin=%s log=%s error=%s log_clean=%u\n", meta.name, path,
                       meta.pin_path, log_path, strerror(-log_rc), meta.log_clean ? 1U : 0U);
                stats.bad_log++;
            } else {
                printf("bad_pin name=%s path=%s pin=%s error=%s\n", meta.name, path, meta.pin_path,
                       strerror(-fd));
                stats.bad_pin++;
            }
            continue;
        }
        if (fd >= 0) {
            if (!inspect_validate_pin_matches_meta(&meta, fd)) {
                bloomd_bpf_close(&fd);
                printf("bad_pin name=%s path=%s pin=%s error=metadata_mismatch\n", meta.name, path,
                       meta.pin_path);
                stats.bad_pin++;
            } else {
                bloomd_bpf_close(&fd);
                if (log_rc == 0) {
                    printf("ok name=%s meta=%s pin=%s log=%s replay_count=%llu log_clean=%u\n",
                           meta.name, path, meta.pin_path, log_path, (unsigned long long)replay_count,
                           meta.log_clean ? 1U : 0U);
                    stats.ok++;
                } else if (log_rc == -ENOENT) {
                    printf("missing_log name=%s meta=%s pin=%s log=%s log_clean=%u\n", meta.name, path,
                           meta.pin_path, log_path, meta.log_clean ? 1U : 0U);
                    stats.missing_log++;
                } else {
                    printf("bad_log name=%s meta=%s pin=%s log=%s error=%s log_clean=%u\n", meta.name,
                           path, meta.pin_path, log_path, strerror(-log_rc), meta.log_clean ? 1U : 0U);
                    stats.bad_log++;
                }
            }
            if (!inspect_contains(loaded_names, loaded_count, meta.name) &&
                inspect_add_name(&loaded_names, &loaded_count, &loaded_cap, meta.name) != 0) {
                fprintf(stderr, "bloominspect: out of memory\n");
                bloomd_free_name_list(meta_entries, meta_count);
                bloomd_free_name_list(pin_entries, pin_count);
                bloomd_free_name_list(loaded_names, loaded_count);
                return 1;
            }
            continue;
        }
        if (fd == -ENOENT) {
            if (log_rc == 0) {
                if (meta.log_clean) {
                    printf("rebuildable name=%s meta=%s pin=%s log=%s replay_count=%llu log_clean=1\n",
                           meta.name, path, meta.pin_path, log_path, (unsigned long long)replay_count);
                    stats.rebuildable++;
                } else {
                    printf("unsafe_rebuild name=%s meta=%s pin=%s log=%s replay_count=%llu log_clean=0\n",
                           meta.name, path, meta.pin_path, log_path, (unsigned long long)replay_count);
                    stats.unsafe_rebuild++;
                }
            } else if (log_rc == -ENOENT) {
                printf("stale_meta path=%s pin=%s log=%s log_clean=%u\n", path, meta.pin_path, log_path,
                       meta.log_clean ? 1U : 0U);
                stats.stale_meta++;
            } else {
                printf("bad_log name=%s meta=%s pin=%s log=%s error=%s log_clean=%u\n", meta.name, path,
                       meta.pin_path, log_path, strerror(-log_rc), meta.log_clean ? 1U : 0U);
                stats.bad_log++;
            }
        } else {
            printf("bad_pin name=%s path=%s pin=%s error=%s\n", meta.name, path, meta.pin_path,
                   strerror(-fd));
            stats.bad_pin++;
        }
    }

    for (size_t i = 0; i < pin_count; ++i) {
        if (!bloomd_name_is_valid(pin_entries[i])) {
            continue;
        }
        if (inspect_contains(loaded_names, loaded_count, pin_entries[i])) {
            continue;
        }
        printf("orphan_pin path=%s/%s\n", pin_root, pin_entries[i]);
        stats.orphan_pin++;
    }

    printf("summary ok=%u invalid_meta=%u missing_log=%u bad_log=%u rebuildable=%u unsafe_rebuild=%u "
           "stale_meta=%u bad_pin=%u orphan_pin=%u\n",
           stats.ok, stats.invalid_meta, stats.missing_log, stats.bad_log, stats.rebuildable,
           stats.unsafe_rebuild, stats.stale_meta, stats.bad_pin, stats.orphan_pin);

    bloomd_free_name_list(meta_entries, meta_count);
    bloomd_free_name_list(pin_entries, pin_count);
    bloomd_free_name_list(loaded_names, loaded_count);
    if (strict && (stats.invalid_meta != 0 || stats.missing_log != 0 || stats.bad_log != 0 ||
                   stats.rebuildable != 0 || stats.unsafe_rebuild != 0 || stats.stale_meta != 0 ||
                   stats.bad_pin != 0 || stats.orphan_pin != 0)) {
        return 1;
    }
    return 0;
}
