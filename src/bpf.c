#include "bloomd.h"

#include <asm/unistd.h>
#include <errno.h>
#include <linux/bpf.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static long (*bloomd_bpf_mock_syscall)(int cmd, void *attr, unsigned int size);

static void bloomd_errmsg(char *errbuf, size_t errcap, const char *msg) {
    if (errbuf != NULL && errcap > 0) {
        snprintf(errbuf, errcap, "%s", msg);
    }
}

static void bloomd_errno_msg(char *errbuf, size_t errcap, const char *prefix) {
    if (errbuf != NULL && errcap > 0) {
        snprintf(errbuf, errcap, "%s: %s", prefix, strerror(errno));
    }
}

static long bloomd_sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size) {
    if (bloomd_bpf_mock_syscall != NULL) {
        return bloomd_bpf_mock_syscall((int)cmd, attr, size);
    }
    return syscall(__NR_bpf, cmd, attr, size);
}

static void bloomd_map_name(const char *name, char out[BPF_OBJ_NAME_LEN]) {
    size_t j = 0;

    memset(out, 0, BPF_OBJ_NAME_LEN);
    out[j++] = 'b';
    out[j++] = 'd';
    out[j++] = '_';
    for (size_t i = 0; name[i] != '\0' && j < BPF_OBJ_NAME_LEN - 1; ++i) {
        char ch = name[i];

        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '_') {
            out[j++] = ch;
        } else {
            out[j++] = '_';
        }
    }
}

void bloomd_bpf_set_mock_syscall(long (*fn)(int cmd, void *attr, unsigned int size)) {
    bloomd_bpf_mock_syscall = fn;
}

void bloomd_bpf_reset_mock_syscall(void) {
    bloomd_bpf_mock_syscall = NULL;
}

int bloomd_bpf_probe_support(char *errbuf, size_t errcap) {
    int fd;
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_BLOOM_FILTER;
    attr.key_size = 0;
    attr.value_size = BLOOMD_DIGEST_SIZE;
    attr.max_entries = 64;
    attr.map_extra = 5;
    bloomd_map_name("probe", attr.map_name);

    fd = (int)bloomd_sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd >= 0) {
        close(fd);
        return 0;
    }
    if (errno == EINVAL || errno == EOPNOTSUPP || errno == ENOTSUP || errno == ENOSYS) {
        bloomd_errmsg(errbuf, errcap,
                      "kernel/userspace does not support BPF_MAP_TYPE_BLOOM_FILTER");
        return -EOPNOTSUPP;
    }
    if (errno == EPERM || errno == EACCES) {
        bloomd_errmsg(errbuf, errcap,
                      "BPF Bloom map probe failed due to insufficient privilege "
                      "(need CAP_BPF/CAP_SYS_ADMIN or equivalent)");
        return -EPERM;
    }
    bloomd_errno_msg(errbuf, errcap, "BPF Bloom map probe failed");
    return -errno;
}

int bloomd_bpf_open_pinned(const char *path) {
    union bpf_attr attr;
    int fd;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    attr.file_flags = 0;
    attr.path_fd = 0;
    fd = (int)bloomd_sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
    if (fd < 0) {
        return -errno;
    }
    return fd;
}

int bloomd_bpf_create_map(const char *name, uint64_t capacity, uint32_t hashes, int *fd_out,
                          char *errbuf, size_t errcap) {
    int fd;
    union bpf_attr attr;

    if (capacity == 0 || capacity > UINT32_MAX) {
        bloomd_errmsg(errbuf, errcap, "capacity must fit in a 32-bit max_entries field");
        return -ERANGE;
    }
    if (hashes > 15U) {
        bloomd_errmsg(errbuf, errcap, "hash count must be between 0 and 15");
        return -ERANGE;
    }
    memset(&attr, 0, sizeof(attr));
    attr.map_type = BPF_MAP_TYPE_BLOOM_FILTER;
    attr.key_size = 0;
    attr.value_size = BLOOMD_DIGEST_SIZE;
    attr.max_entries = (uint32_t)capacity;
    attr.map_extra = hashes & 0x0fU;
    bloomd_map_name(name, attr.map_name);

    fd = (int)bloomd_sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
    if (fd < 0) {
        bloomd_errno_msg(errbuf, errcap, "BPF_MAP_CREATE failed");
        return -errno;
    }
    *fd_out = fd;
    return 0;
}

int bloomd_bpf_pin_map(int fd, const char *path, char *errbuf, size_t errcap) {
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.pathname = (uint64_t)(uintptr_t)path;
    attr.bpf_fd = (uint32_t)fd;
    attr.file_flags = 0;
    attr.path_fd = 0;
    if (bloomd_sys_bpf(BPF_OBJ_PIN, &attr, sizeof(attr)) != 0) {
        bloomd_errno_msg(errbuf, errcap, "BPF_OBJ_PIN failed");
        return -errno;
    }
    return 0;
}

int bloomd_bpf_add_digest(int fd, const uint8_t digest[BLOOMD_DIGEST_SIZE], char *errbuf,
                          size_t errcap) {
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = 0;
    attr.value = (uint64_t)(uintptr_t)digest;
    attr.flags = BPF_ANY;
    if (bloomd_sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr)) != 0) {
        bloomd_errno_msg(errbuf, errcap, "BPF_MAP_UPDATE_ELEM failed");
        return -errno;
    }
    return 0;
}

int bloomd_bpf_check_digest(int fd, const uint8_t digest[BLOOMD_DIGEST_SIZE], bool *present_out,
                            char *errbuf, size_t errcap) {
    union bpf_attr attr;

    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)fd;
    attr.key = 0;
    attr.value = (uint64_t)(uintptr_t)digest;
    attr.flags = 0;
    if (bloomd_sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)) == 0) {
        *present_out = true;
        return 0;
    }
    if (errno == ENOENT) {
        *present_out = false;
        return 0;
    }
    bloomd_errno_msg(errbuf, errcap, "BPF_MAP_LOOKUP_ELEM failed");
    return -errno;
}

int bloomd_bpf_get_map_info(int fd, struct bloomd_bpf_map_info *info_out, char *errbuf, size_t errcap) {
    union bpf_attr attr;
    struct bpf_map_info info;

    if (fd < 0 || info_out == NULL) {
        return -EINVAL;
    }
    memset(&attr, 0, sizeof(attr));
    memset(&info, 0, sizeof(info));
    attr.info.bpf_fd = (uint32_t)fd;
    attr.info.info_len = sizeof(info);
    attr.info.info = (uint64_t)(uintptr_t)&info;
    if (bloomd_sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)) != 0) {
        bloomd_errno_msg(errbuf, errcap, "BPF_OBJ_GET_INFO_BY_FD failed");
        return -errno;
    }
    memset(info_out, 0, sizeof(*info_out));
    info_out->type = info.type;
    info_out->key_size = info.key_size;
    info_out->value_size = info.value_size;
    info_out->max_entries = info.max_entries;
    info_out->map_extra = info.map_extra;
    return 0;
}

int bloomd_bpf_unpin(const char *path, char *errbuf, size_t errcap) {
    if (unlink(path) != 0) {
        if (errno == ENOENT) {
            return 0;
        }
        bloomd_errno_msg(errbuf, errcap, "unlink failed");
        return -errno;
    }
    return 0;
}

void bloomd_bpf_close(int *fd) {
    if (fd != NULL && *fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}
