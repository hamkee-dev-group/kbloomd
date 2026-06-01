#include "bloomd.h"

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define JUNK_BODY_LEN 128U

static const char *kBloomdBinary = "build/bloomd";
static const char *kSocketPath = "/tmp/bloomd-test-reject-bodies.sock";
static const char *kPinRoot = "/sys/fs/bpf/bloomd-test-reject-bodies";
static const char *kMetaRoot = "/tmp/bloomd-test-reject-bodies-meta";

static void sleep_ms(unsigned ms) {
    struct timespec ts;

    ts.tv_sec = ms / 1000U;
    ts.tv_nsec = (long)(ms % 1000U) * 1000000L;
    nanosleep(&ts, NULL);
}

static int connect_socket(const char *path) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (connect(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;

        close(fd);
        return -saved;
    }
    return fd;
}

static int wait_for_socket(const char *path, pid_t child, unsigned timeout_ms) {
    unsigned elapsed = 0;

    while (elapsed < timeout_ms) {
        int rc;
        int status;
        pid_t w;

        w = waitpid(child, &status, WNOHANG);
        if (w == child) {
            return -ECHILD;
        }
        rc = connect_socket(path);
        if (rc >= 0) {
            return rc;
        }
        sleep_ms(50);
        elapsed += 50;
    }
    return -ETIMEDOUT;
}

static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t got = write(fd, p + off, len - off);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (got == 0) {
            return -EPIPE;
        }
        off += (size_t)got;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    size_t off = 0;

    while (off < len) {
        ssize_t got = read(fd, p + off, len - off);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (got == 0) {
            return -ECONNRESET;
        }
        off += (size_t)got;
    }
    return 0;
}

static void build_header(struct bloomd_frame_header *hdr, uint8_t opcode, uint32_t request_id,
                         uint32_t body_len) {
    memset(hdr, 0, sizeof(*hdr));
    memcpy(hdr->magic, BLOOMD_PROTOCOL_MAGIC, 4);
    hdr->version = BLOOMD_PROTOCOL_VERSION;
    hdr->opcode = opcode;
    hdr->flags = 0;
    hdr->status = 0;
    hdr->request_id = request_id;
    hdr->body_len = body_len;
}

static int send_request_with_body(int fd, uint8_t opcode, uint32_t request_id, const void *body,
                                  uint32_t body_len) {
    struct bloomd_frame_header hdr;
    int rc;

    build_header(&hdr, opcode, request_id, body_len);
    rc = write_all(fd, &hdr, sizeof(hdr));
    if (rc != 0) {
        return rc;
    }
    if (body_len == 0) {
        return 0;
    }
    return write_all(fd, body, body_len);
}

static int read_response(int fd, struct bloomd_frame_header *hdr_out, uint8_t *body, size_t cap) {
    int rc;

    rc = read_all(fd, hdr_out, sizeof(*hdr_out));
    if (rc != 0) {
        return rc;
    }
    if (hdr_out->body_len > cap) {
        return -E2BIG;
    }
    if (hdr_out->body_len == 0) {
        return 0;
    }
    return read_all(fd, body, hdr_out->body_len);
}

static int run_reject_case(int fd, uint8_t opcode, uint32_t request_id, const char *label) {
    uint8_t junk[JUNK_BODY_LEN];
    struct bloomd_frame_header resp_hdr;
    uint8_t resp_body[256];
    int rc;

    memset(junk, 0x5a, sizeof(junk));
    rc = send_request_with_body(fd, opcode, request_id, junk, JUNK_BODY_LEN);
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s send: %s\n", label, strerror(-rc));
        return -1;
    }
    rc = read_response(fd, &resp_hdr, resp_body, sizeof(resp_body));
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s read response: %s\n", label, strerror(-rc));
        return -1;
    }
    if (resp_hdr.status != BLOOMD_STATUS_BAD_REQUEST) {
        fprintf(stderr, "FAIL: %s expected status BAD_REQUEST (%d), got %u\n", label,
                BLOOMD_STATUS_BAD_REQUEST, resp_hdr.status);
        return -1;
    }
    if (resp_hdr.request_id != request_id) {
        fprintf(stderr, "FAIL: %s response request_id mismatch (got %u, expected %u)\n", label,
                resp_hdr.request_id, request_id);
        return -1;
    }
    printf("PASS: %s rejected with BAD_REQUEST\n", label);
    return 0;
}

static int run_valid_ping(int fd) {
    struct bloomd_frame_header resp_hdr;
    uint8_t resp_body[64];
    int rc;

    rc = send_request_with_body(fd, BLOOMD_OP_PING, 99U, NULL, 0);
    if (rc != 0) {
        fprintf(stderr, "FAIL: liveness PING send: %s\n", strerror(-rc));
        return -1;
    }
    rc = read_response(fd, &resp_hdr, resp_body, sizeof(resp_body));
    if (rc != 0) {
        fprintf(stderr, "FAIL: liveness PING read: %s\n", strerror(-rc));
        return -1;
    }
    if (resp_hdr.status != BLOOMD_STATUS_OK) {
        fprintf(stderr, "FAIL: liveness PING status %u (expected OK)\n", resp_hdr.status);
        return -1;
    }
    if (resp_hdr.body_len != 4 || memcmp(resp_body, "PONG", 4) != 0) {
        fprintf(stderr, "FAIL: liveness PING body mismatch\n");
        return -1;
    }
    printf("PASS: daemon still alive, PING returned PONG\n");
    return 0;
}

static void cleanup_paths(void) {
    unlink(kSocketPath);
}

int main(void) {
    pid_t child;
    int fd;
    int test_rc = 0;
    int status;

    cleanup_paths();
    mkdir(kMetaRoot, 0700);

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        execl(kBloomdBinary, kBloomdBinary, "--foreground", "--socket", kSocketPath, "--pin-root",
              kPinRoot, "--meta-root", kMetaRoot, (char *)NULL);
        perror("execl");
        _exit(127);
    }

    fd = wait_for_socket(kSocketPath, child, 3000U);
    if (fd < 0) {
        if (fd == -ECHILD) {
            fprintf(stderr,
                    "SKIP: bloomd failed to start (likely missing CAP_BPF / bpffs access)\n");
        } else {
            fprintf(stderr, "SKIP: bloomd did not open socket: %s\n", strerror(-fd));
            kill(child, SIGTERM);
        }
        waitpid(child, &status, 0);
        cleanup_paths();
        return 0;
    }

    if (run_reject_case(fd, BLOOMD_OP_PING, 1U, "PING with body") != 0) {
        test_rc = 1;
    }
    if (run_reject_case(fd, BLOOMD_OP_LIST, 2U, "LIST with body") != 0) {
        test_rc = 1;
    }
    if (run_reject_case(fd, BLOOMD_OP_STATS, 3U, "STATS with body") != 0) {
        test_rc = 1;
    }
    if (kill(child, 0) != 0) {
        fprintf(stderr, "FAIL: daemon died after bad-request frames\n");
        test_rc = 1;
    }
    if (run_valid_ping(fd) != 0) {
        test_rc = 1;
    }

    close(fd);
    kill(child, SIGTERM);
    waitpid(child, &status, 0);
    cleanup_paths();
    return test_rc;
}
