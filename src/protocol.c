#include "bloomd.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

static void bloomd_store_u16(void *dst, uint16_t value) {
    uint8_t *p = dst;
    p[0] = (uint8_t)(value & 0xffU);
    p[1] = (uint8_t)((value >> 8) & 0xffU);
}

static void bloomd_store_u32(void *dst, uint32_t value) {
    uint8_t *p = dst;
    p[0] = (uint8_t)(value & 0xffU);
    p[1] = (uint8_t)((value >> 8) & 0xffU);
    p[2] = (uint8_t)((value >> 16) & 0xffU);
    p[3] = (uint8_t)((value >> 24) & 0xffU);
}

static void bloomd_store_u64(void *dst, uint64_t value) {
    uint8_t *p = dst;
    for (size_t i = 0; i < sizeof(value); ++i) {
        p[i] = (uint8_t)((value >> (8U * i)) & 0xffU);
    }
}

uint16_t bloomd_load_u16(const void *src) {
    const uint8_t *p = src;
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

uint32_t bloomd_load_u32(const void *src) {
    const uint8_t *p = src;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

uint64_t bloomd_load_u64(const void *src) {
    const uint8_t *p = src;
    uint64_t out = 0;

    for (size_t i = 0; i < sizeof(out); ++i) {
        out |= ((uint64_t)p[i] << (8U * i));
    }
    return out;
}

double bloomd_load_double(const void *src) {
    double value = 0.0;
    memcpy(&value, src, sizeof(value));
    return value;
}

void bloomd_buffer_init(struct bloomd_buffer *buf) {
    memset(buf, 0, sizeof(*buf));
}

void bloomd_buffer_free(struct bloomd_buffer *buf) {
    free(buf->data);
    memset(buf, 0, sizeof(*buf));
}

int bloomd_buffer_reserve(struct bloomd_buffer *buf, size_t cap) {
    uint8_t *next;

    if (cap <= buf->cap) {
        return 0;
    }
    next = realloc(buf->data, cap);
    if (next == NULL) {
        return -ENOMEM;
    }
    buf->data = next;
    buf->cap = cap;
    return 0;
}

int bloomd_buffer_append(struct bloomd_buffer *buf, const void *data, size_t len) {
    int rc;

    if (len == 0) {
        return 0;
    }
    if (buf->len + len > BLOOMD_MAX_FRAME_BODY) {
        return -E2BIG;
    }
    rc = bloomd_buffer_reserve(buf, buf->len + len);
    if (rc != 0) {
        return rc;
    }
    memcpy(buf->data + buf->len, data, len);
    buf->len += len;
    return 0;
}

int bloomd_buffer_append_u16(struct bloomd_buffer *buf, uint16_t value) {
    uint8_t tmp[2];

    bloomd_store_u16(tmp, value);
    return bloomd_buffer_append(buf, tmp, sizeof(tmp));
}

int bloomd_buffer_append_u32(struct bloomd_buffer *buf, uint32_t value) {
    uint8_t tmp[4];

    bloomd_store_u32(tmp, value);
    return bloomd_buffer_append(buf, tmp, sizeof(tmp));
}

int bloomd_buffer_append_u64(struct bloomd_buffer *buf, uint64_t value) {
    uint8_t tmp[8];

    bloomd_store_u64(tmp, value);
    return bloomd_buffer_append(buf, tmp, sizeof(tmp));
}

int bloomd_buffer_append_double(struct bloomd_buffer *buf, double value) {
    return bloomd_buffer_append(buf, &value, sizeof(value));
}

int bloomd_buffer_append_str(struct bloomd_buffer *buf, const char *str) {
    return bloomd_buffer_append(buf, str, strlen(str));
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

int bloomd_read_frame(int fd, struct bloomd_request_view *req, struct bloomd_buffer *storage) {
    int rc;

    memset(req, 0, sizeof(*req));
    storage->len = 0;

    rc = bloomd_read_all(fd, &req->header, sizeof(req->header));
    if (rc != 0) {
        return rc;
    }
    rc = bloomd_header_is_valid(&req->header);
    if (rc != 0) {
        return rc;
    }
    if (req->header.body_len == 0) {
        req->body = NULL;
        return 0;
    }
    rc = bloomd_buffer_reserve(storage, req->header.body_len);
    if (rc != 0) {
        return rc;
    }
    rc = bloomd_read_all(fd, storage->data, req->header.body_len);
    if (rc != 0) {
        return rc;
    }
    storage->len = req->header.body_len;
    req->body = storage->data;
    return 0;
}

int bloomd_write_response(int fd, const struct bloomd_response *resp) {
    struct bloomd_frame_header hdr = resp->header;
    struct iovec iov[2];
    size_t offset = 0;
    size_t iovcnt = resp->body.len == 0 ? 1U : 2U;

    hdr.body_len = (uint32_t)resp->body.len;
    iov[0].iov_base = &hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = resp->body.data;
    iov[1].iov_len = resp->body.len;

    while (iovcnt > 0) {
        ssize_t wrote = writev(fd, &iov[offset], (int)iovcnt);

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
        while (iovcnt > 0 && (size_t)wrote >= iov[offset].iov_len) {
            wrote -= (ssize_t)iov[offset].iov_len;
            offset++;
            iovcnt--;
        }
        if (iovcnt == 0 || wrote == 0) {
            continue;
        }
        iov[offset].iov_base = (uint8_t *)iov[offset].iov_base + wrote;
        iov[offset].iov_len -= (size_t)wrote;
    }
    return 0;
}

void bloomd_response_init(struct bloomd_response *resp, uint8_t opcode, uint32_t request_id) {
    memset(resp, 0, sizeof(*resp));
    memcpy(resp->header.magic, BLOOMD_PROTOCOL_MAGIC, 4);
    resp->header.version = BLOOMD_PROTOCOL_VERSION;
    resp->header.opcode = opcode;
    resp->header.flags = 0x01U;
    resp->header.status = BLOOMD_STATUS_OK;
    resp->header.request_id = request_id;
    bloomd_buffer_init(&resp->body);
}

void bloomd_response_reset(struct bloomd_response *resp, uint8_t opcode, uint32_t request_id) {
    resp->body.len = 0;
    memcpy(resp->header.magic, BLOOMD_PROTOCOL_MAGIC, 4);
    resp->header.version = BLOOMD_PROTOCOL_VERSION;
    resp->header.opcode = opcode;
    resp->header.flags = 0x01U;
    resp->header.status = BLOOMD_STATUS_OK;
    resp->header.request_id = request_id;
    resp->header.body_len = 0;
}

void bloomd_response_free(struct bloomd_response *resp) {
    bloomd_buffer_free(&resp->body);
}

int bloomd_response_error(struct bloomd_response *resp, uint8_t status, uint32_t code,
                          const char *message) {
    struct bloomd_error_response err;
    int rc;

    if (message == NULL) {
        message = "";
    }
    resp->body.len = 0;
    resp->header.flags = 0x03U;
    resp->header.status = status;
    err.code = code;
    err.message_len = (uint32_t)strlen(message);

    rc = bloomd_buffer_append_u32(&resp->body, err.code);
    if (rc != 0) {
        return rc;
    }
    rc = bloomd_buffer_append_u32(&resp->body, err.message_len);
    if (rc != 0) {
        return rc;
    }
    return bloomd_buffer_append(&resp->body, message, err.message_len);
}

int bloomd_protocol_read_name(const uint8_t *buf, size_t len, const char **name, uint16_t *name_len,
                              size_t *consumed) {
    uint16_t nlen;

    if (len < sizeof(uint16_t)) {
        return -EINVAL;
    }
    nlen = bloomd_load_u16(buf);
    if (nlen == 0 || nlen > BLOOMD_MAX_NAME_LEN) {
        return -EINVAL;
    }
    if (len < sizeof(uint16_t) + nlen) {
        return -EINVAL;
    }
    *name = (const char *)(buf + sizeof(uint16_t));
    *name_len = nlen;
    *consumed = sizeof(uint16_t) + nlen;
    return 0;
}

int bloomd_protocol_read_payload(const uint8_t *buf, size_t len, const uint8_t **payload,
                                 uint32_t *payload_len, size_t *consumed) {
    uint32_t plen;

    if (len < sizeof(uint32_t)) {
        return -EINVAL;
    }
    plen = bloomd_load_u32(buf);
    if (plen > BLOOMD_MAX_FRAME_BODY) {
        return -E2BIG;
    }
    if (len < sizeof(uint32_t) + plen) {
        return -EINVAL;
    }
    *payload = buf + sizeof(uint32_t);
    *payload_len = plen;
    *consumed = sizeof(uint32_t) + plen;
    return 0;
}

const char *bloomd_status_string(uint8_t status) {
    switch (status) {
    case BLOOMD_STATUS_OK:
        return "ok";
    case BLOOMD_STATUS_BAD_REQUEST:
        return "bad_request";
    case BLOOMD_STATUS_TOO_LARGE:
        return "too_large";
    case BLOOMD_STATUS_NOT_FOUND:
        return "not_found";
    case BLOOMD_STATUS_EXISTS:
        return "exists";
    case BLOOMD_STATUS_UNSUPPORTED:
        return "unsupported";
    case BLOOMD_STATUS_IO:
        return "io";
    case BLOOMD_STATUS_BPF:
        return "bpf";
    case BLOOMD_STATUS_NAME:
        return "name";
    case BLOOMD_STATUS_STATE:
        return "state";
    case BLOOMD_STATUS_PERM:
        return "perm";
    case BLOOMD_STATUS_INTERNAL:
        return "internal";
    default:
        return "unknown";
    }
}

const char *bloomd_errno_string(int code) {
    switch (code) {
    case BLOOMD_ERR_NONE:
        return "none";
    case BLOOMD_ERR_PARSE:
        return "parse_error";
    case BLOOMD_ERR_RANGE:
        return "range_error";
    case BLOOMD_ERR_TIMEOUT:
        return "timeout";
    case BLOOMD_ERR_SHORT_IO:
        return "short_io";
    case BLOOMD_ERR_UNSUPPORTED_KERNEL:
        return "unsupported_kernel";
    case BLOOMD_ERR_BPF_PRIVS:
        return "bpf_privileges";
    case BLOOMD_ERR_BPFFS:
        return "bpffs";
    case BLOOMD_ERR_METADATA:
        return "metadata";
    default:
        return "unknown";
    }
}
