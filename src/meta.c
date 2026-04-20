#include "bloomd.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int bloomd_meta_assign_string(char *dst, size_t dst_sz, const char *value) {
    if (strlen(value) >= dst_sz) {
        return -ENAMETOOLONG;
    }
    snprintf(dst, dst_sz, "%s", value);
    return 0;
}

static int bloomd_meta_parse_u32(const char *value, uint32_t *out) {
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > UINT32_MAX) {
        return -EINVAL;
    }
    *out = (uint32_t)parsed;
    return 0;
}

static int bloomd_meta_parse_u64(const char *value, uint64_t *out) {
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        return -EINVAL;
    }
    *out = (uint64_t)parsed;
    return 0;
}

static int bloomd_meta_parse_double(const char *value, double *out) {
    char *end = NULL;
    double parsed;

    errno = 0;
    parsed = strtod(value, &end);
    if (errno != 0 || end == value || *end != '\0') {
        return -EINVAL;
    }
    *out = parsed;
    return 0;
}

static void bloomd_trim_newline(char *line) {
    size_t len = strlen(line);

    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }
}

int bloomd_meta_write_atomic(const struct bloomd_filter_meta *meta) {
    char tmp_path[PATH_MAX];
    char dir_path[PATH_MAX];
    char body[2048];
    int fd;
    int dfd;
    int body_len;
    int n;

    body_len = snprintf(body, sizeof(body),
                        "version=%u\n"
                        "name=%s\n"
                        "backend=%s\n"
                        "digest=%s\n"
                        "capacity=%llu\n"
                        "error_rate=%.17g\n"
                        "hashes=%u\n"
                        "value_size=%u\n"
                        "has_data=%u\n"
                        "log_clean=%u\n"
                        "pin_path=%s\n",
                        meta->metadata_version, meta->name, meta->backend, meta->digest,
                        (unsigned long long)meta->capacity, meta->error_rate, meta->hashes,
                        meta->value_size, meta->has_data ? 1U : 0U, meta->log_clean ? 1U : 0U,
                        meta->pin_path);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        return -ENAMETOOLONG;
    }
    n = snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.%ld", meta->meta_path, (long)getpid());
    if (n < 0 || (size_t)n >= sizeof(tmp_path)) {
        return -ENAMETOOLONG;
    }

    fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -errno;
    }
    n = bloomd_write_all(fd, body, (size_t)body_len);
    if (n != 0) {
        int saved = -n;

        close(fd);
        unlink(tmp_path);
        return -saved;
    }
    if (fdatasync(fd) != 0) {
        int saved = errno;

        close(fd);
        unlink(tmp_path);
        return -saved;
    }
    close(fd);
    if (rename(tmp_path, meta->meta_path) != 0) {
        int saved = errno;

        unlink(tmp_path);
        return -saved;
    }

    snprintf(dir_path, sizeof(dir_path), "%s", meta->meta_path);
    for (char *p = dir_path + strlen(dir_path); p > dir_path; --p) {
        if (*p == '/') {
            *p = '\0';
            break;
        }
    }
    dfd = open(dir_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)fsync(dfd);
        close(dfd);
    }
    return 0;
}

int bloomd_meta_read_file(const char *path, struct bloomd_filter_meta *meta) {
    FILE *fp;
    char line[1024];
    bool have_name = false;
    bool have_backend = false;
    bool have_digest = false;
    bool have_capacity = false;
    bool have_rate = false;
    bool have_hashes = false;
    bool have_value_size = false;
    bool have_has_data = false;
    bool have_log_clean = false;
    bool have_pin_path = false;

    memset(meta, 0, sizeof(*meta));
    meta->has_data = true;
    meta->log_clean = false;
    fp = fopen(path, "r");
    if (fp == NULL) {
        return -errno;
    }
    while (fgets(line, sizeof(line), fp) != NULL) {
        char *eq;
        char *key;
        char *value;

        bloomd_trim_newline(line);
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        eq = strchr(line, '=');
        if (eq == NULL) {
            fclose(fp);
            return -EINVAL;
        }
        *eq = '\0';
        key = line;
        value = eq + 1;
        if (strcmp(key, "version") == 0) {
            if (meta->metadata_version != 0 || bloomd_meta_parse_u32(value, &meta->metadata_version) != 0) {
                fclose(fp);
                return -EINVAL;
            }
        } else if (strcmp(key, "name") == 0) {
            if (have_name || bloomd_meta_assign_string(meta->name, sizeof(meta->name), value) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_name = true;
        } else if (strcmp(key, "backend") == 0) {
            if (have_backend ||
                bloomd_meta_assign_string(meta->backend, sizeof(meta->backend), value) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_backend = true;
        } else if (strcmp(key, "digest") == 0) {
            if (have_digest ||
                bloomd_meta_assign_string(meta->digest, sizeof(meta->digest), value) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_digest = true;
        } else if (strcmp(key, "capacity") == 0) {
            if (have_capacity || bloomd_meta_parse_u64(value, &meta->capacity) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_capacity = true;
        } else if (strcmp(key, "error_rate") == 0) {
            if (have_rate || bloomd_meta_parse_double(value, &meta->error_rate) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_rate = true;
        } else if (strcmp(key, "hashes") == 0) {
            if (have_hashes || bloomd_meta_parse_u32(value, &meta->hashes) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_hashes = true;
        } else if (strcmp(key, "value_size") == 0) {
            if (have_value_size || bloomd_meta_parse_u32(value, &meta->value_size) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_value_size = true;
        } else if (strcmp(key, "has_data") == 0) {
            uint32_t has_data = 0;

            if (have_has_data || bloomd_meta_parse_u32(value, &has_data) != 0 ||
                (has_data != 0 && has_data != 1)) {
                fclose(fp);
                return -EINVAL;
            }
            meta->has_data = has_data != 0;
            have_has_data = true;
        } else if (strcmp(key, "log_clean") == 0) {
            uint32_t log_clean = 0;

            if (have_log_clean || bloomd_meta_parse_u32(value, &log_clean) != 0 ||
                (log_clean != 0 && log_clean != 1)) {
                fclose(fp);
                return -EINVAL;
            }
            meta->log_clean = log_clean != 0;
            have_log_clean = true;
        } else if (strcmp(key, "pin_path") == 0) {
            if (have_pin_path ||
                bloomd_meta_assign_string(meta->pin_path, sizeof(meta->pin_path), value) != 0) {
                fclose(fp);
                return -EINVAL;
            }
            have_pin_path = true;
        } else {
            fclose(fp);
            return -EINVAL;
        }
    }
    fclose(fp);

    if (!(have_name && have_backend && have_digest && have_capacity && have_rate && have_hashes &&
          have_value_size && have_pin_path)) {
        return -EINVAL;
    }
    if (meta->metadata_version != BLOOMD_METADATA_VERSION) {
        return -EINVAL;
    }
    if (!bloomd_name_is_valid(meta->name)) {
        return -EINVAL;
    }
    if (strcmp(meta->backend, BLOOMD_BACKEND_NAME) != 0 ||
        strcmp(meta->digest, BLOOMD_DIGEST_NAME) != 0) {
        return -EINVAL;
    }
    if (meta->value_size != BLOOMD_DIGEST_SIZE || meta->capacity == 0 || meta->hashes > 15U ||
        !isfinite(meta->error_rate) || meta->error_rate <= 0.0 || meta->error_rate >= 1.0) {
        return -EINVAL;
    }
    if (!have_log_clean) {
        meta->log_clean = meta->has_data ? false : true;
    }
    snprintf(meta->meta_path, sizeof(meta->meta_path), "%s", path);
    return 0;
}

int bloomd_meta_delete(const char *path) {
    return bloomd_remove_path_if_exists(path);
}

int bloomd_meta_recover_stale(const char *path) {
    char recovered[PATH_MAX];
    time_t now = time(NULL);

    if (snprintf(recovered, sizeof(recovered), "%s.stale.%ld", path, (long)now) >=
        (int)sizeof(recovered)) {
        return -ENAMETOOLONG;
    }
    if (rename(path, recovered) != 0) {
        return -errno;
    }
    return 0;
}
