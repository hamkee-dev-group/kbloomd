#include "bloomd.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int bloomd_log_reset(const char *path) {
    int fd;

    fd = open(path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0644);
    if (fd < 0) {
        return -errno;
    }
    if (fsync(fd) != 0) {
        int saved = errno;

        close(fd);
        return -saved;
    }
    close(fd);
    return 0;
}

int bloomd_log_open_append(const char *path) {
    int fd = open(path, O_CREAT | O_APPEND | O_WRONLY | O_CLOEXEC, 0644);

    if (fd < 0) {
        return -errno;
    }
    return fd;
}

int bloomd_log_open_create(const char *path) {
    int fd = open(path, O_CREAT | O_TRUNC | O_APPEND | O_WRONLY | O_CLOEXEC, 0644);

    if (fd < 0) {
        return -errno;
    }
    return fd;
}

int bloomd_log_append_fd(int fd, const uint8_t digest[BLOOMD_DIGEST_SIZE]) {
    if (fd < 0) {
        return -EINVAL;
    }
    return bloomd_write_all(fd, digest, BLOOMD_DIGEST_SIZE);
}

int bloomd_log_buffer_append(int fd, uint8_t buf[BLOOMD_LOG_BUFFER_CAP], size_t *buf_len_io,
                             const uint8_t digest[BLOOMD_DIGEST_SIZE]) {
    int rc;

    if (fd < 0 || buf == NULL || buf_len_io == NULL) {
        return -EINVAL;
    }
    if (*buf_len_io > BLOOMD_LOG_BUFFER_CAP) {
        return -EINVAL;
    }
    if (*buf_len_io + BLOOMD_DIGEST_SIZE > BLOOMD_LOG_BUFFER_CAP) {
        rc = bloomd_write_all(fd, buf, *buf_len_io);
        if (rc != 0) {
            return rc;
        }
        *buf_len_io = 0;
    }
    memcpy(buf + *buf_len_io, digest, BLOOMD_DIGEST_SIZE);
    *buf_len_io += BLOOMD_DIGEST_SIZE;
    return 0;
}

int bloomd_log_buffer_flush(int fd, uint8_t buf[BLOOMD_LOG_BUFFER_CAP], size_t *buf_len_io, bool sync) {
    int rc;

    if (fd < 0 || buf == NULL || buf_len_io == NULL) {
        return -EINVAL;
    }
    if (*buf_len_io > 0) {
        rc = bloomd_write_all(fd, buf, *buf_len_io);
        if (rc != 0) {
            return rc;
        }
        *buf_len_io = 0;
    }
    if (!sync) {
        return 0;
    }
    return bloomd_log_sync(fd);
}

int bloomd_log_sync(int fd) {
    if (fd < 0) {
        return -EINVAL;
    }
    if (fsync(fd) != 0) {
        return -errno;
    }
    return 0;
}

int bloomd_log_truncate(int fd, off_t length, bool sync) {
    if (fd < 0 || length < 0) {
        return -EINVAL;
    }
    if (ftruncate(fd, length) != 0) {
        return -errno;
    }
    if (!sync) {
        return 0;
    }
    return bloomd_log_sync(fd);
}

void bloomd_log_close(int *fd, bool sync) {
    if (fd == NULL || *fd < 0) {
        return;
    }
    if (sync) {
        (void)bloomd_log_sync(*fd);
    }
    close(*fd);
    *fd = -1;
}

static int log_replay_impl(const char *path, bloomd_log_replay_cb cb, void *ctx,
                           uint64_t *count_out, bool truncate_partial) {
    uint8_t digest[BLOOMD_DIGEST_SIZE];
    int fd;
    uint64_t count = 0;

    if (cb == NULL) {
        return -EINVAL;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    for (;;) {
        size_t off = 0;

        while (off < sizeof(digest)) {
            ssize_t got = read(fd, digest + off, sizeof(digest) - off);

            if (got < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return -errno;
            }
            if (got == 0) {
                if (off == 0) {
                    close(fd);
                    if (count_out != NULL) {
                        *count_out = count;
                    }
                    return 0;
                }
                close(fd);
                if (truncate_partial &&
                    truncate(path, (off_t)(count * BLOOMD_DIGEST_SIZE)) != 0) {
                    return -errno;
                }
                if (count_out != NULL) {
                    *count_out = count;
                }
                return 0;
            }
            off += (size_t)got;
        }
        if (cb(digest, ctx) != 0) {
            close(fd);
            return -EINVAL;
        }
        count++;
    }
}

int bloomd_log_replay(const char *path, bloomd_log_replay_cb cb, void *ctx, uint64_t *count_out) {
    return log_replay_impl(path, cb, ctx, count_out, true);
}

int bloomd_log_replay_readonly(const char *path, bloomd_log_replay_cb cb, void *ctx,
                               uint64_t *count_out) {
    return log_replay_impl(path, cb, ctx, count_out, false);
}

int bloomd_log_delete(const char *path) {
    return bloomd_remove_path_if_exists(path);
}
