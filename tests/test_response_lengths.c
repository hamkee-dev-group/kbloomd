#include "bloomd.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *kBloomctlBinary = "build/bloomctl";
static const char *kSocketPath = "/tmp/bloomd-test-response-lengths.sock";

static int read_all_fd(int fd, void *buf, size_t len) {
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

static int write_all_fd(int fd, const void *buf, size_t len) {
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

static int make_listener(const char *path) {
    int fd;
    struct sockaddr_un addr;

    unlink(path);
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -errno;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        int saved = errno;

        close(fd);
        return -saved;
    }
    if (listen(fd, 1) != 0) {
        int saved = errno;

        close(fd);
        return -saved;
    }
    return fd;
}

static int serve_ok_response(int listen_fd, uint8_t opcode, const uint8_t *body, uint32_t body_len) {
    int client_fd;
    struct bloomd_frame_header hdr;
    uint8_t scratch[256];
    uint32_t remaining;
    int rc;

    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        return -errno;
    }
    rc = read_all_fd(client_fd, &hdr, sizeof(hdr));
    if (rc != 0) {
        close(client_fd);
        return rc;
    }
    if (memcmp(hdr.magic, BLOOMD_PROTOCOL_MAGIC, 4) != 0 || hdr.version != BLOOMD_PROTOCOL_VERSION) {
        close(client_fd);
        return -EPROTO;
    }
    if (hdr.opcode != opcode) {
        close(client_fd);
        return -EPROTO;
    }
    remaining = hdr.body_len;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(scratch) ? remaining : sizeof(scratch);

        rc = read_all_fd(client_fd, scratch, chunk);
        if (rc != 0) {
            close(client_fd);
            return rc;
        }
        remaining -= (uint32_t)chunk;
    }

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, BLOOMD_PROTOCOL_MAGIC, 4);
    hdr.version = BLOOMD_PROTOCOL_VERSION;
    hdr.opcode = opcode;
    hdr.flags = 0x01U;
    hdr.status = BLOOMD_STATUS_OK;
    hdr.request_id = 1U;
    hdr.body_len = body_len;
    rc = write_all_fd(client_fd, &hdr, sizeof(hdr));
    if (rc == 0 && body_len > 0) {
        rc = write_all_fd(client_fd, body, body_len);
    }
    close(client_fd);
    return rc;
}

static int run_case(const char *label, char *const argv[], uint8_t opcode, const uint8_t *body,
                    uint32_t body_len, bool expect_ok) {
    int listen_fd;
    pid_t child;
    int devnull;
    int rc;
    int status;

    listen_fd = make_listener(kSocketPath);
    if (listen_fd < 0) {
        fprintf(stderr, "FAIL: %s: make_listener: %s\n", label, strerror(-listen_fd));
        return 1;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        close(listen_fd);
        unlink(kSocketPath);
        return 1;
    }
    if (child == 0) {
        close(listen_fd);
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execv(kBloomctlBinary, argv);
        perror("execv");
        _exit(127);
    }

    rc = serve_ok_response(listen_fd, opcode, body, body_len);
    close(listen_fd);
    unlink(kSocketPath);
    if (rc != 0) {
        fprintf(stderr, "FAIL: %s: serve_ok_response: %s\n", label, strerror(-rc));
        kill(child, SIGTERM);
        waitpid(child, &status, 0);
        return 1;
    }
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status)) {
        fprintf(stderr, "FAIL: %s: bloomctl did not exit normally (status=%d)\n", label, status);
        return 1;
    }
    if (expect_ok && WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: %s: bloomctl exited %d, expected 0\n", label, WEXITSTATUS(status));
        return 1;
    }
    if (!expect_ok && WEXITSTATUS(status) == 0) {
        fprintf(stderr, "FAIL: %s: bloomctl exited 0, expected nonzero\n", label);
        return 1;
    }
    printf("PASS: %s (body_len=%u) → exit %d\n", label, body_len, WEXITSTATUS(status));
    return 0;
}

int main(void) {
    char *const madd_argv[] = {(char *)kBloomctlBinary, "-s", (char *)kSocketPath, "madd", "users",
                               "a", "b", NULL};
    char *const mcheck_argv[] = {(char *)kBloomctlBinary, "-s", (char *)kSocketPath, "mcheck",
                                 "users", "a", "b", NULL};
    char *const info_argv[] = {(char *)kBloomctlBinary, "-s", (char *)kSocketPath, "info", "users",
                               NULL};
    const uint8_t batch_one_byte[] = {2};
    const uint8_t batch_count_mismatch[] = {5, 0};
    const uint8_t batch_valid[] = {2, 0, 1, 0};
    uint8_t info_short[10];
    uint8_t info_header_only[72];
    uint8_t info_valid[72 + 5 + 9 + 13];
    int rc = 0;

    memset(info_short, 0, sizeof(info_short));
    memset(info_header_only, 0, sizeof(info_header_only));
    info_header_only[0] = 5; /* name_len=5 but no name bytes follow */
    memset(info_valid, 0, sizeof(info_valid));
    info_valid[0] = 5;
    info_valid[2] = 9;
    info_valid[4] = 13;
    memcpy(info_valid + 72, "users", 5);
    memcpy(info_valid + 77, "bpf_bloom", 9);
    memcpy(info_valid + 86, "siphash128-v1", 13);

    if (run_case("madd empty OK body", madd_argv, BLOOMD_OP_MADD, NULL, 0, false) != 0) {
        rc = 1;
    }
    if (run_case("mcheck empty OK body", mcheck_argv, BLOOMD_OP_MCHECK, NULL, 0, false) != 0) {
        rc = 1;
    }
    if (run_case("madd 1-byte OK body", madd_argv, BLOOMD_OP_MADD, batch_one_byte,
                 sizeof(batch_one_byte), false) != 0) {
        rc = 1;
    }
    if (run_case("mcheck count mismatch", mcheck_argv, BLOOMD_OP_MCHECK, batch_count_mismatch,
                 sizeof(batch_count_mismatch), false) != 0) {
        rc = 1;
    }
    if (run_case("madd valid body", madd_argv, BLOOMD_OP_MADD, batch_valid, sizeof(batch_valid),
                 true) != 0) {
        rc = 1;
    }
    if (run_case("info empty OK body", info_argv, BLOOMD_OP_INFO, NULL, 0, false) != 0) {
        rc = 1;
    }
    if (run_case("info short OK body", info_argv, BLOOMD_OP_INFO, info_short, sizeof(info_short),
                 false) != 0) {
        rc = 1;
    }
    if (run_case("info string length mismatch", info_argv, BLOOMD_OP_INFO, info_header_only,
                 sizeof(info_header_only), false) != 0) {
        rc = 1;
    }
    if (run_case("info valid body", info_argv, BLOOMD_OP_INFO, info_valid, sizeof(info_valid),
                 true) != 0) {
        rc = 1;
    }
    return rc;
}
