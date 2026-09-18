#define main bloomd_main
#include "../src/daemon.c"
#undef main

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static int stage_ping_response(struct bloomd_client *client, int fd, uint32_t request_id) {
    int rc;

    bloomd_client_init(client, fd);
    bloomd_response_reset(&client->resp, BLOOMD_OP_PING, request_id);
    rc = bloomd_handle_ping(&client->resp);
    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_handle_ping: %s\n", strerror(-rc));
        return 1;
    }
    rc = bloomd_client_prepare_write(client);
    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_client_prepare_write: %s\n", strerror(-rc));
        return 1;
    }
    if (client->state != BLOOMD_CLIENT_WRITE_RESPONSE) {
        fprintf(stderr, "FAIL: state expected WRITE_RESPONSE, got %d\n", (int)client->state);
        return 1;
    }
    return 0;
}

static int run_peer_closed_case(void) {
    int sv[2];
    struct bloomd_client client;
    struct bloomd_stats stats;
    int rc;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        return 1;
    }
    rc = bloomd_install_signal_handlers();
    if (rc != 0) {
        fprintf(stderr, "FAIL: bloomd_install_signal_handlers: %s\n", strerror(-rc));
        return 1;
    }
    memset(&stats, 0, sizeof(stats));
    if (stage_ping_response(&client, sv[0], 1) != 0) {
        return 1;
    }
    close(sv[1]);

    rc = bloomd_client_drive_write(&client, &stats);
    if (rc != -EPIPE) {
        fprintf(stderr, "FAIL: drive_write on closed peer expected -EPIPE, got %d\n", rc);
        return 1;
    }
    if (stats.responses != 0) {
        fprintf(stderr, "FAIL: responses expected 0, got %llu\n",
                (unsigned long long)stats.responses);
        return 1;
    }
    bloomd_client_close(&client);
    if (client.fd != -1 || client.state != BLOOMD_CLIENT_EMPTY) {
        fprintf(stderr, "FAIL: client not reset after close (fd=%d state=%d)\n", client.fd,
                (int)client.state);
        return 1;
    }
    printf("PASS: write to closed peer returns -EPIPE instead of raising SIGPIPE\n");
    return 0;
}

static int run_peer_open_case(void) {
    int sv[2];
    struct bloomd_client client;
    struct bloomd_stats stats;
    struct bloomd_frame_header hdr;
    uint8_t body[sizeof("PONG") - 1];
    uint8_t extra;
    int rc;

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        return 1;
    }
    memset(&stats, 0, sizeof(stats));
    if (stage_ping_response(&client, sv[0], 2) != 0) {
        return 1;
    }

    rc = bloomd_client_drive_write(&client, &stats);
    if (rc != 1) {
        fprintf(stderr, "FAIL: drive_write on open peer expected 1, got %d\n", rc);
        return 1;
    }
    if (stats.responses != 1) {
        fprintf(stderr, "FAIL: responses expected 1, got %llu\n",
                (unsigned long long)stats.responses);
        return 1;
    }
    rc = read_all_fd(sv[1], &hdr, sizeof(hdr));
    if (rc != 0) {
        fprintf(stderr, "FAIL: read header: %s\n", strerror(-rc));
        return 1;
    }
    if (hdr.opcode != BLOOMD_OP_PING || hdr.request_id != 2 || hdr.status != BLOOMD_STATUS_OK) {
        fprintf(stderr, "FAIL: header opcode=%u request_id=%u status=%u\n", hdr.opcode,
                hdr.request_id, hdr.status);
        return 1;
    }
    if (hdr.body_len != sizeof(body)) {
        fprintf(stderr, "FAIL: body_len expected %zu, got %u\n", sizeof(body), hdr.body_len);
        return 1;
    }
    rc = read_all_fd(sv[1], body, sizeof(body));
    if (rc != 0) {
        fprintf(stderr, "FAIL: read body: %s\n", strerror(-rc));
        return 1;
    }
    if (memcmp(body, "PONG", sizeof(body)) != 0) {
        fprintf(stderr, "FAIL: body expected 'PONG', got '%.*s'\n", (int)sizeof(body), body);
        return 1;
    }
    bloomd_client_close(&client);
    if (read(sv[1], &extra, 1) != 0) {
        fprintf(stderr, "FAIL: trailing bytes after body\n");
        return 1;
    }
    close(sv[1]);
    printf("PASS: PONG response delivered to open peer\n");
    return 0;
}

static int run_signal_case(void) {
    if (bloomd_stop != 0) {
        fprintf(stderr, "FAIL: bloomd_stop set before any signal\n");
        return 1;
    }
    raise(SIGTERM);
    if (bloomd_stop != 1) {
        fprintf(stderr, "FAIL: SIGTERM did not set bloomd_stop\n");
        return 1;
    }
    bloomd_stop = 0;
    raise(SIGINT);
    if (bloomd_stop != 1) {
        fprintf(stderr, "FAIL: SIGINT did not set bloomd_stop\n");
        return 1;
    }
    printf("PASS: SIGTERM and SIGINT still request shutdown\n");
    return 0;
}

int main(void) {
    if (run_peer_closed_case() != 0) {
        return 1;
    }
    if (run_peer_open_case() != 0) {
        return 1;
    }
    if (run_signal_case() != 0) {
        return 1;
    }
    return 0;
}
