#include "bloomd.h"

#include <dirent.h>
#include <errno.h>
#include <linux/magic.h>
#include <math.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <unistd.h>

void bloomd_config_defaults(struct bloomd_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    snprintf(cfg->socket_path, sizeof(cfg->socket_path), "%s", BLOOMD_DEFAULT_SOCKET);
    snprintf(cfg->pin_root, sizeof(cfg->pin_root), "%s", BLOOMD_DEFAULT_PIN_ROOT);
    snprintf(cfg->meta_root, sizeof(cfg->meta_root), "%s", BLOOMD_DEFAULT_META_ROOT);
    cfg->socket_mode = BLOOMD_DEFAULT_SOCKET_MODE;
    cfg->log_sync_mode = BLOOMD_LOG_SYNC_PERIODIC;
    cfg->foreground = true;
    cfg->fail_if_unsupported = true;
}

bool bloomd_name_is_valid(const char *name) {
    size_t len;

    if (name == NULL) {
        return false;
    }
    len = strlen(name);
    if (len == 0 || len > BLOOMD_MAX_NAME_LEN) {
        return false;
    }
    for (size_t i = 0; i < len; ++i) {
        const unsigned char ch = (unsigned char)name[i];

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_') {
            continue;
        }
        return false;
    }
    return true;
}

int bloomd_validate_filter_name(const char *name, char *errbuf, size_t errcap) {
    if (!bloomd_name_is_valid(name)) {
        if (errbuf != NULL && errcap > 0) {
            snprintf(errbuf, errcap,
                     "invalid filter name: use 1-%u chars from [A-Za-z0-9_-]",
                     BLOOMD_MAX_NAME_LEN);
        }
        return -EINVAL;
    }
    return 0;
}

static int bloomd_join_path(const char *root, const char *leaf, const char *suffix, char *out,
                            size_t out_sz) {
    int n;

    n = snprintf(out, out_sz, "%s/%s%s", root, leaf, suffix);
    if (n < 0 || (size_t)n >= out_sz) {
        return -ENAMETOOLONG;
    }
    return 0;
}

int bloomd_build_pin_path(const char *root, const char *name, char *out, size_t out_sz) {
    return bloomd_join_path(root, name, "", out, out_sz);
}

int bloomd_build_meta_path(const char *root, const char *name, char *out, size_t out_sz) {
    return bloomd_join_path(root, name, ".meta", out, out_sz);
}

int bloomd_build_log_path(const char *root, const char *name, char *out, size_t out_sz) {
    return bloomd_join_path(root, name, ".digests", out, out_sz);
}

int bloomd_ensure_dir(const char *path, mode_t mode, bool allow_existing) {
    char tmp[PATH_MAX];
    size_t len;

    if (path == NULL || path[0] == '\0') {
        return -EINVAL;
    }
    len = strlen(path);
    if (len >= sizeof(tmp)) {
        return -ENAMETOOLONG;
    }
    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p != '\0'; ++p) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(tmp, mode) != 0 && errno != EEXIST) {
            return -errno;
        }
        *p = '/';
    }
    if (mkdir(tmp, mode) != 0) {
        if (errno == EEXIST && allow_existing) {
            return 0;
        }
        return -errno;
    }
    return 0;
}

bool bloomd_is_bpffs(const char *path) {
    struct statfs st;

    if (statfs(path, &st) != 0) {
        return false;
    }
    return (unsigned long)st.f_type == BPF_FS_MAGIC;
}

int bloomd_write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;

    while (len > 0) {
        ssize_t wrote = write(fd, p, len);

        if (wrote < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -ETIMEDOUT;
            }
            return -errno;
        }
        if (wrote == 0) {
            return -EPIPE;
        }
        p += (size_t)wrote;
        len -= (size_t)wrote;
    }
    return 0;
}

int bloomd_read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;

    while (len > 0) {
        ssize_t got = read(fd, p, len);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -ETIMEDOUT;
            }
            return -errno;
        }
        if (got == 0) {
            return -ECONNRESET;
        }
        p += (size_t)got;
        len -= (size_t)got;
    }
    return 0;
}

int bloomd_set_socket_timeouts(int fd, int timeout_ms) {
    struct timeval tv;

    if (timeout_ms <= 0) {
        return -EINVAL;
    }
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return -errno;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        return -errno;
    }
    return 0;
}

int bloomd_parse_octal_mode(const char *text, mode_t *mode_out) {
    char *end = NULL;
    unsigned long value;

    if (text == NULL || text[0] == '\0' || mode_out == NULL) {
        return -EINVAL;
    }
    errno = 0;
    value = strtoul(text, &end, 8);
    if (errno != 0 || end == text || *end != '\0' || value > 0777U) {
        return -EINVAL;
    }
    *mode_out = (mode_t)value;
    return 0;
}

int bloomd_parse_log_sync_mode(const char *text, enum bloomd_log_sync_mode *mode_out) {
    if (text == NULL || mode_out == NULL) {
        return -EINVAL;
    }
    if (strcmp(text, "periodic") == 0) {
        *mode_out = BLOOMD_LOG_SYNC_PERIODIC;
        return 0;
    }
    if (strcmp(text, "always") == 0) {
        *mode_out = BLOOMD_LOG_SYNC_ALWAYS;
        return 0;
    }
    return -EINVAL;
}

uint32_t bloomd_hashes_for_error_rate(double error_rate) {
    double hashes;

    if (!isfinite(error_rate) || error_rate <= 0.0 || error_rate >= 1.0) {
        return 0;
    }
    hashes = ceil(log2(1.0 / error_rate));
    if (hashes < 1.0) {
        return 1U;
    }
    if (hashes > 15.0) {
        return 15U;
    }
    return (uint32_t)hashes;
}

int bloomd_remove_path_if_exists(const char *path) {
    if (unlink(path) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        return -errno;
    }
    return 0;
}

int bloomd_list_dir(const char *path, char ***names_out, size_t *count_out) {
    DIR *dir;
    struct dirent *ent;
    char **names = NULL;
    size_t len = 0;
    size_t cap = 0;

    dir = opendir(path);
    if (dir == NULL) {
        return -errno;
    }
    while ((ent = readdir(dir)) != NULL) {
        char **next;
        char *copy;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }
        if (len == cap) {
            size_t new_cap = cap == 0 ? 8 : cap * 2;

            next = realloc(names, new_cap * sizeof(*names));
            if (next == NULL) {
                closedir(dir);
                bloomd_free_name_list(names, len);
                return -ENOMEM;
            }
            names = next;
            cap = new_cap;
        }
        copy = strdup(ent->d_name);
        if (copy == NULL) {
            closedir(dir);
            bloomd_free_name_list(names, len);
            return -ENOMEM;
        }
        names[len++] = copy;
    }
    closedir(dir);
    *names_out = names;
    *count_out = len;
    return 0;
}

void bloomd_free_name_list(char **names, size_t count) {
    if (names == NULL) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free(names[i]);
    }
    free(names);
}

void bloomd_filter_set_init(struct bloomd_filter_set *set) {
    memset(set, 0, sizeof(*set));
    set->last_index = SIZE_MAX;
}

void bloomd_filter_set_free(struct bloomd_filter_set *set) {
    if (set == NULL) {
        return;
    }
    for (size_t i = 0; i < set->len; ++i) {
        (void)bloomd_log_buffer_flush(set->items[i].log_fd, set->items[i].log_buf,
                                      &set->items[i].log_buf_len, true);
        bloomd_log_close(&set->items[i].log_fd, false);
        bloomd_bpf_close(&set->items[i].map_fd);
    }
    free(set->items);
    memset(set, 0, sizeof(*set));
    set->last_index = SIZE_MAX;
}

struct bloomd_filter *bloomd_filter_set_find(struct bloomd_filter_set *set, const char *name) {
    return bloomd_filter_set_find_n(set, name, strlen(name));
}

struct bloomd_filter *bloomd_filter_set_find_n(struct bloomd_filter_set *set, const char *name,
                                               size_t name_len) {
    if (set->last_index < set->len &&
        set->items[set->last_index].meta.name[name_len] == '\0' &&
        memcmp(set->items[set->last_index].meta.name, name, name_len) == 0) {
        return &set->items[set->last_index];
    }
    for (size_t i = 0; i < set->len; ++i) {
        if (set->items[i].meta.name[name_len] == '\0' &&
            memcmp(set->items[i].meta.name, name, name_len) == 0) {
            set->last_index = i;
            return &set->items[i];
        }
    }
    return NULL;
}

int bloomd_filter_set_add(struct bloomd_filter_set *set, const struct bloomd_filter *filter) {
    struct bloomd_filter *next;

    if (set->len == set->cap) {
        size_t new_cap = set->cap == 0 ? 8 : set->cap * 2;

        next = realloc(set->items, new_cap * sizeof(*next));
        if (next == NULL) {
            return -ENOMEM;
        }
        set->items = next;
        set->cap = new_cap;
    }
    set->items[set->len++] = *filter;
    set->last_index = set->len - 1;
    return 0;
}

int bloomd_filter_set_remove(struct bloomd_filter_set *set, const char *name) {
    return bloomd_filter_set_remove_n(set, name, strlen(name));
}

int bloomd_filter_set_remove_n(struct bloomd_filter_set *set, const char *name, size_t name_len) {
    for (size_t i = 0; i < set->len; ++i) {
        if (!(set->items[i].meta.name[name_len] == '\0' &&
              memcmp(set->items[i].meta.name, name, name_len) == 0)) {
            continue;
        }
        (void)bloomd_log_buffer_flush(set->items[i].log_fd, set->items[i].log_buf,
                                      &set->items[i].log_buf_len, false);
        bloomd_log_close(&set->items[i].log_fd, false);
        bloomd_bpf_close(&set->items[i].map_fd);
        if (i + 1 < set->len) {
            memmove(&set->items[i], &set->items[i + 1],
                    (set->len - (i + 1)) * sizeof(set->items[0]));
        }
        set->len--;
        if (set->len == 0) {
            set->last_index = SIZE_MAX;
        } else if (set->last_index == i || set->last_index >= set->len) {
            set->last_index = SIZE_MAX;
        } else if (set->last_index > i) {
            set->last_index--;
        }
        return 0;
    }
    return -ENOENT;
}
