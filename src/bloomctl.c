#include "bloomd.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int bloomctl_connect(const char *socket_path) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;

        close(fd);
        return -saved;
    }
    return fd;
}

static int bloomctl_send_request(int fd, uint8_t opcode, uint32_t request_id, struct bloomd_buffer *body,
                                 struct bloomd_request_view *resp_view, struct bloomd_buffer *resp_storage) {
    struct bloomd_response req;
    int rc;

    bloomd_response_init(&req, opcode, request_id);
    req.header.flags = 0;
    req.body = *body;
    rc = bloomd_write_response(fd, &req);
    if (rc != 0) {
        return rc;
    }
    return bloomd_read_frame(fd, resp_view, resp_storage);
}

static int bloomctl_append_name(struct bloomd_buffer *body, const char *name) {
    size_t len = strlen(name);

    if (!bloomd_name_is_valid(name)) {
        fprintf(stderr, "invalid filter name: %s\n", name);
        return -EINVAL;
    }
    if (len > UINT16_MAX) {
        return -EINVAL;
    }
    return bloomd_buffer_append(body, name, len);
}

static int bloomctl_build_name_request(struct bloomd_buffer *body, const char *name) {
    struct bloomd_name_request hdr = {0};
    int rc;

    hdr.name_len = (uint16_t)strlen(name);
    rc = bloomd_buffer_append(body, &hdr, sizeof(hdr));
    if (rc != 0) {
        return rc;
    }
    return bloomctl_append_name(body, name);
}

static int bloomctl_build_payload_request(struct bloomd_buffer *body, const char *name,
                                          const uint8_t *payload, size_t payload_len) {
    struct bloomd_payload_request hdr = {0};
    int rc;

    if (payload_len > UINT32_MAX) {
        return -EINVAL;
    }
    hdr.name_len = (uint16_t)strlen(name);
    hdr.payload_len = (uint32_t)payload_len;
    rc = bloomd_buffer_append(body, &hdr, sizeof(hdr));
    if (rc != 0) {
        return rc;
    }
    rc = bloomctl_append_name(body, name);
    if (rc != 0) {
        return rc;
    }
    return bloomd_buffer_append(body, payload, payload_len);
}

static int bloomctl_print_error(const struct bloomd_request_view *resp) {
    uint32_t code;
    uint32_t msg_len;

    if (resp->header.body_len < 8) {
        fprintf(stderr, "server error: malformed error body\n");
        return 1;
    }
    code = bloomd_load_u32(resp->body);
    msg_len = bloomd_load_u32(resp->body + 4);
    if ((uint64_t)8 + msg_len > resp->header.body_len) {
        fprintf(stderr, "server error: malformed error body\n");
        return 1;
    }
    fprintf(stderr, "server error [%s/%s]: %.*s\n", bloomd_status_string(resp->header.status),
            bloomd_errno_string((int)code), (int)msg_len, (const char *)(resp->body + 8));
    return 1;
}

static int bloomctl_expect_body_len(const struct bloomd_request_view *resp, uint32_t expected,
                                    const char *what) {
    if (resp->header.body_len != expected) {
        fprintf(stderr, "%s: malformed response body length %u\n", what, resp->header.body_len);
        return 1;
    }
    return 0;
}

static int bloomctl_command_create(struct bloomd_buffer *body, int argc, char **argv, int start) {
    struct bloomd_create_request req = {0};
    int rc;

    if (argc - start < 3) {
        fprintf(stderr, "usage: bloomctl create NAME CAPACITY ERROR_RATE [HASHES]\n");
        return -EINVAL;
    }
    req.capacity = strtoull(argv[start + 1], NULL, 10);
    req.error_rate = strtod(argv[start + 2], NULL);
    req.hashes = (argc - start >= 4) ? (uint32_t)strtoul(argv[start + 3], NULL, 10) : 0;
    req.name_len = (uint16_t)strlen(argv[start]);
    rc = bloomd_buffer_append(body, &req, sizeof(req));
    if (rc != 0) {
        return rc;
    }
    return bloomctl_append_name(body, argv[start]);
}

static int bloomctl_command_batch(struct bloomd_buffer *body, const char *name, int item_count,
                                  char **items) {
    struct bloomd_batch_request hdr = {0};
    int rc;

    if (item_count <= 0 || item_count > (int)BLOOMD_MAX_BATCH_ITEMS) {
        fprintf(stderr, "batch item count must be between 1 and %u\n", BLOOMD_MAX_BATCH_ITEMS);
        return -EINVAL;
    }
    hdr.name_len = (uint16_t)strlen(name);
    hdr.item_count = (uint16_t)item_count;
    rc = bloomd_buffer_append(body, &hdr, sizeof(hdr));
    if (rc != 0) {
        return rc;
    }
    rc = bloomctl_append_name(body, name);
    if (rc != 0) {
        return rc;
    }
    for (int i = 0; i < item_count; ++i) {
        uint32_t len = (uint32_t)strlen(items[i]);

        rc = bloomd_buffer_append_u32(body, len);
        if (rc != 0) {
            return rc;
        }
        rc = bloomd_buffer_append(body, items[i], len);
        if (rc != 0) {
            return rc;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *socket_path = BLOOMD_DEFAULT_SOCKET;
    const char *cmd;
    struct bloomd_buffer req_body;
    struct bloomd_buffer resp_storage;
    struct bloomd_request_view resp;
    int fd;
    int rc;
    uint8_t opcode = 0;
    uint32_t request_id = 1;
    int start = 1;

    if (argc >= 3 && strcmp(argv[1], "-s") == 0) {
        socket_path = argv[2];
        start = 3;
    }
    if (argc > start && strcmp(argv[start], "--version") == 0) {
        printf("bloomctl %s\n", BLOOMD_VERSION);
        return 0;
    }
    if (argc <= start) {
        fprintf(stderr, "usage: bloomctl [-s SOCKET] COMMAND ...\n");
        return 2;
    }
    cmd = argv[start];
    bloomd_buffer_init(&req_body);
    bloomd_buffer_init(&resp_storage);

    if (strcmp(cmd, "ping") == 0) {
        opcode = BLOOMD_OP_PING;
    } else if (strcmp(cmd, "create") == 0) {
        opcode = BLOOMD_OP_CREATE;
        rc = bloomctl_command_create(&req_body, argc, argv, start + 1);
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "add") == 0) {
        opcode = BLOOMD_OP_ADD;
        if (argc - start != 3) {
            fprintf(stderr, "usage: bloomctl add NAME PAYLOAD\n");
            return 2;
        }
        rc = bloomctl_build_payload_request(&req_body, argv[start + 1], (const uint8_t *)argv[start + 2],
                                            strlen(argv[start + 2]));
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "check") == 0) {
        opcode = BLOOMD_OP_CHECK;
        if (argc - start != 3) {
            fprintf(stderr, "usage: bloomctl check NAME PAYLOAD\n");
            return 2;
        }
        rc = bloomctl_build_payload_request(&req_body, argv[start + 1], (const uint8_t *)argv[start + 2],
                                            strlen(argv[start + 2]));
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "madd") == 0) {
        opcode = BLOOMD_OP_MADD;
        if (argc - start < 3) {
            fprintf(stderr, "usage: bloomctl madd NAME PAYLOAD...\n");
            return 2;
        }
        rc = bloomctl_command_batch(&req_body, argv[start + 1], argc - start - 2, &argv[start + 2]);
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "mcheck") == 0) {
        opcode = BLOOMD_OP_MCHECK;
        if (argc - start < 3) {
            fprintf(stderr, "usage: bloomctl mcheck NAME PAYLOAD...\n");
            return 2;
        }
        rc = bloomctl_command_batch(&req_body, argv[start + 1], argc - start - 2, &argv[start + 2]);
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "info") == 0) {
        opcode = BLOOMD_OP_INFO;
        if (argc - start != 2) {
            fprintf(stderr, "usage: bloomctl info NAME\n");
            return 2;
        }
        rc = bloomctl_build_name_request(&req_body, argv[start + 1]);
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "list") == 0) {
        opcode = BLOOMD_OP_LIST;
    } else if (strcmp(cmd, "drop") == 0) {
        opcode = BLOOMD_OP_DROP;
        if (argc - start != 2) {
            fprintf(stderr, "usage: bloomctl drop NAME\n");
            return 2;
        }
        rc = bloomctl_build_name_request(&req_body, argv[start + 1]);
        if (rc != 0) {
            return 2;
        }
    } else if (strcmp(cmd, "stats") == 0) {
        opcode = BLOOMD_OP_STATS;
    } else {
        fprintf(stderr, "unknown command: %s\n", cmd);
        return 2;
    }

    fd = bloomctl_connect(socket_path);
    if (fd < 0) {
        fprintf(stderr, "connect failed: %s\n", strerror(-fd));
        return 1;
    }
    rc = bloomctl_send_request(fd, opcode, request_id, &req_body, &resp, &resp_storage);
    if (rc != 0) {
        fprintf(stderr, "request failed: %s\n", strerror(-rc));
        close(fd);
        return 1;
    }
    close(fd);

    if (resp.header.status != BLOOMD_STATUS_OK) {
        return bloomctl_print_error(&resp);
    }

    if (opcode == BLOOMD_OP_PING) {
        printf("%.*s\n", (int)resp.header.body_len, (const char *)resp.body);
    } else if (opcode == BLOOMD_OP_ADD || opcode == BLOOMD_OP_CHECK) {
        if (bloomctl_expect_body_len(&resp, 1, "add/check") != 0) {
            return 1;
        }
        printf("%u\n", resp.header.body_len > 0 ? resp.body[0] : 0U);
    } else if (opcode == BLOOMD_OP_MADD || opcode == BLOOMD_OP_MCHECK) {
        uint16_t count = bloomd_load_u16(resp.body);
        const uint8_t *vals = resp.body + 2;

        if (resp.header.body_len < 2 || resp.header.body_len != (uint32_t)(2 + count)) {
            fprintf(stderr, "batch: malformed response body length %u\n", resp.header.body_len);
            return 1;
        }
        for (uint16_t i = 0; i < count; ++i) {
            printf("%u%s", vals[i], (i + 1 == count) ? "\n" : " ");
        }
    } else if (opcode == BLOOMD_OP_INFO) {
        const uint8_t *p = resp.body;
        uint16_t name_len = bloomd_load_u16(p);
        uint16_t backend_len = bloomd_load_u16(p + 2);
        uint16_t digest_len = bloomd_load_u16(p + 4);
        uint64_t capacity = bloomd_load_u64(p + 8);
        double error_rate = bloomd_load_double(p + 16);
        uint32_t hashes = bloomd_load_u32(p + 24);
        uint32_t value_size = bloomd_load_u32(p + 28);
        uint64_t add_calls = bloomd_load_u64(p + 32);
        uint64_t check_calls = bloomd_load_u64(p + 40);
        uint64_t batch_add_calls = bloomd_load_u64(p + 48);
        uint64_t batch_check_calls = bloomd_load_u64(p + 56);
        uint32_t pin_len = bloomd_load_u32(p + 64);
        uint32_t state_flags = bloomd_load_u32(p + 68);
        const char *name = (const char *)(p + 72);
        const char *backend = name + name_len;
        const char *digest = backend + backend_len;
        const char *pin = digest + digest_len;

        if (resp.header.body_len < 72U ||
            (uint64_t)72 + name_len + backend_len + digest_len + pin_len != resp.header.body_len) {
            fprintf(stderr, "info: malformed response body length %u\n", resp.header.body_len);
            return 1;
        }
        printf("name=%.*s\nbackend=%.*s\ndigest=%.*s\ncapacity=%llu\nerror_rate=%.17g\nhashes=%u\n"
               "value_size=%u\npin_path=%.*s\nadd_calls=%llu\ncheck_calls=%llu\n"
               "batch_add_calls=%llu\nbatch_check_calls=%llu\nstate_flags=%u\ndurable=%u\nmetadata_only=%u\n"
               "log_clean=%u\nlog_dirty=%u\n",
               name_len, name, backend_len, backend, digest_len, digest,
               (unsigned long long)capacity, error_rate, hashes, value_size, pin_len, pin,
               (unsigned long long)add_calls, (unsigned long long)check_calls,
               (unsigned long long)batch_add_calls, (unsigned long long)batch_check_calls,
               state_flags, (state_flags & BLOOMD_FILTER_STATE_DURABLE) != 0,
               (state_flags & BLOOMD_FILTER_STATE_METADATA_ONLY) != 0,
               (state_flags & BLOOMD_FILTER_STATE_LOG_CLEAN) != 0,
               (state_flags & BLOOMD_FILTER_STATE_LOG_DIRTY) != 0);
    } else if (opcode == BLOOMD_OP_LIST) {
        uint32_t count;
        size_t off = 4;

        if (resp.header.body_len < 4) {
            fprintf(stderr, "list: malformed response body length %u\n", resp.header.body_len);
            return 1;
        }
        count = bloomd_load_u32(resp.body);
        for (uint32_t i = 0; i < count; ++i) {
            uint16_t len;

            if (off + 2 > resp.header.body_len) {
                fprintf(stderr, "list: truncated entry header\n");
                return 1;
            }
            len = bloomd_load_u16(resp.body + off);

            off += 2;
            if (off + len > resp.header.body_len) {
                fprintf(stderr, "list: truncated entry body\n");
                return 1;
            }
            printf("%.*s\n", len, (const char *)(resp.body + off));
            off += len;
        }
        if (off != resp.header.body_len) {
            fprintf(stderr, "list: trailing bytes in response\n");
            return 1;
        }
    } else if (opcode == BLOOMD_OP_STATS) {
        const uint8_t *p = resp.body;

        if (bloomctl_expect_body_len(&resp, 100, "stats") != 0) {
            return 1;
        }
        printf("requests=%llu\nresponses=%llu\nerrors=%llu\naccepted_connections=%llu\n"
               "filters_loaded=%llu\nfilters_created=%llu\nfilters_dropped=%llu\n"
               "orphan_meta=%llu\norphan_pin=%llu\nfilter_count=%u\nmetadata_only_filters=%u\n"
               "durable_filters=%u\nempty_pool_hits=%llu\nempty_pool_misses=%llu\n",
               (unsigned long long)bloomd_load_u64(p),
               (unsigned long long)bloomd_load_u64(p + 8),
               (unsigned long long)bloomd_load_u64(p + 16),
               (unsigned long long)bloomd_load_u64(p + 24),
               (unsigned long long)bloomd_load_u64(p + 32),
               (unsigned long long)bloomd_load_u64(p + 40),
               (unsigned long long)bloomd_load_u64(p + 48),
               (unsigned long long)bloomd_load_u64(p + 56),
               (unsigned long long)bloomd_load_u64(p + 64),
               bloomd_load_u32(p + 72),
               bloomd_load_u32(p + 76),
               bloomd_load_u32(p + 80),
               (unsigned long long)bloomd_load_u64(p + 84),
               (unsigned long long)bloomd_load_u64(p + 92));
    }

    bloomd_buffer_free(&req_body);
    bloomd_buffer_free(&resp_storage);
    return 0;
}
