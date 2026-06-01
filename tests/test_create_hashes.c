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
#include <time.h>
#include <unistd.h>

static const char *kBloomctlBinary = "build/bloomctl";
static const char *kSocketPath = "/tmp/bloomd-test-create-hashes.sock";

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

static int send_ok_response(int client_fd, uint8_t opcode, uint32_t request_id) {
    struct bloomd_frame_header hdr;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, BLOOMD_PROTOCOL_MAGIC, 4);
    hdr.version = BLOOMD_PROTOCOL_VERSION;
    hdr.opcode = opcode;
    hdr.flags = 0x01U;
    hdr.status = BLOOMD_STATUS_OK;
    hdr.request_id = request_id;
    hdr.body_len = 0;
    return write_all_fd(client_fd, &hdr, sizeof(hdr));
}

struct captured_create {
    uint64_t capacity;
    double error_rate;
    uint32_t hashes;
    uint16_t name_len;
    char name[BLOOMD_MAX_NAME_LEN + 1];
};

static int capture_create(int listen_fd, struct captured_create *out) {
    int client_fd;
    struct bloomd_frame_header hdr;
    uint8_t body[sizeof(struct bloomd_create_request) + BLOOMD_MAX_NAME_LEN];
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
    if (hdr.opcode != BLOOMD_OP_CREATE) {
        close(client_fd);
        return -EPROTO;
    }
    if (hdr.body_len < sizeof(struct bloomd_create_request) || hdr.body_len > sizeof(body)) {
        close(client_fd);
        return -EPROTO;
    }
    rc = read_all_fd(client_fd, body, hdr.body_len);
    if (rc != 0) {
        close(client_fd);
        return rc;
    }
    out->capacity = bloomd_load_u64(body);
    out->error_rate = bloomd_load_double(body + 8);
    out->hashes = bloomd_load_u32(body + 16);
    out->name_len = bloomd_load_u16(body + 20);
    if ((size_t)sizeof(struct bloomd_create_request) + out->name_len != hdr.body_len) {
        close(client_fd);
        return -EPROTO;
    }
    if (out->name_len > BLOOMD_MAX_NAME_LEN) {
        close(client_fd);
        return -EPROTO;
    }
    memcpy(out->name, body + sizeof(struct bloomd_create_request), out->name_len);
    out->name[out->name_len] = '\0';

    rc = send_ok_response(client_fd, BLOOMD_OP_CREATE, hdr.request_id);
    close(client_fd);
    return rc;
}

static int run_capture_case(uint32_t expected_hashes, bool include_hashes_arg) {
    int listen_fd;
    pid_t child;
    struct captured_create captured;
    int rc;
    int status;
    int test_rc = 0;

    listen_fd = make_listener(kSocketPath);
    if (listen_fd < 0) {
        fprintf(stderr, "FAIL: make_listener: %s\n", strerror(-listen_fd));
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
        if (include_hashes_arg) {
            char hashes_buf[16];

            snprintf(hashes_buf, sizeof(hashes_buf), "%u", expected_hashes);
            execl(kBloomctlBinary, kBloomctlBinary, "-s", kSocketPath, "create", "users", "100000",
                  "0.001", hashes_buf, (char *)NULL);
        } else {
            execl(kBloomctlBinary, kBloomctlBinary, "-s", kSocketPath, "create", "users", "100000",
                  "0.001", (char *)NULL);
        }
        perror("execl");
        _exit(127);
    }

    memset(&captured, 0, sizeof(captured));
    rc = capture_create(listen_fd, &captured);
    close(listen_fd);
    unlink(kSocketPath);
    if (rc != 0) {
        fprintf(stderr, "FAIL: capture_create: %s\n", strerror(-rc));
        kill(child, SIGTERM);
        waitpid(child, &status, 0);
        return 1;
    }
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FAIL: bloomctl exited abnormally (status=%d)\n", status);
        test_rc = 1;
    }
    if (captured.capacity != 100000ULL) {
        fprintf(stderr, "FAIL: capacity expected 100000, got %llu\n",
                (unsigned long long)captured.capacity);
        test_rc = 1;
    }
    if (captured.error_rate != 0.001) {
        fprintf(stderr, "FAIL: error_rate expected 0.001, got %.17g\n", captured.error_rate);
        test_rc = 1;
    }
    if (captured.hashes != expected_hashes) {
        fprintf(stderr, "FAIL: hashes expected %u, got %u\n", expected_hashes, captured.hashes);
        test_rc = 1;
    }
    if (captured.name_len != 5 || memcmp(captured.name, "users", 5) != 0) {
        fprintf(stderr, "FAIL: name expected 'users', got '%.*s'\n", (int)captured.name_len,
                captured.name);
        test_rc = 1;
    }
    if (test_rc == 0) {
        printf("PASS: bloomctl create users 100000 0.001%s%s → hashes=%u on the wire\n",
               include_hashes_arg ? " " : "",
               include_hashes_arg ? (expected_hashes == 3 ? "3" : "?") : "",
               captured.hashes);
    }
    return test_rc;
}

static int run_reject_case_too_few_args(void) {
    pid_t child;
    int devnull;
    int status;

    child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }
    if (child == 0) {
        devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execl(kBloomctlBinary, kBloomctlBinary, "-s", kSocketPath, "create", "users", "100000",
              (char *)NULL);
        perror("execl");
        _exit(127);
    }
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 1;
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        fprintf(stderr, "FAIL: bloomctl create with only 2 args should have failed\n");
        return 1;
    }
    printf("PASS: bloomctl create users 100000 (2 args) rejected\n");
    return 0;
}

int main(void) {
    int rc = 0;

    if (run_capture_case(3U, true) != 0) {
        rc = 1;
    }
    if (run_capture_case(0U, false) != 0) {
        rc = 1;
    }
    if (run_reject_case_too_few_args() != 0) {
        rc = 1;
    }
    return rc;
}
