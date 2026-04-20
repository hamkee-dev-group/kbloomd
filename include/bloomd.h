#ifndef BLOOMD_H
#define BLOOMD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BLOOMD_PROTOCOL_MAGIC "BLM1"
#define BLOOMD_PROTOCOL_VERSION 1U
#define BLOOMD_MAX_FRAME_BODY (1024U * 1024U)
#define BLOOMD_MAX_NAME_LEN 63U
#define BLOOMD_MAX_FILTERS 1024U
#define BLOOMD_MAX_BATCH_ITEMS 1024U
#define BLOOMD_DIGEST_SIZE 16U
#define BLOOMD_METADATA_VERSION 1U
#define BLOOMD_REQ_TIMEOUT_MS 5000
#define BLOOMD_DEFAULT_SOCKET "/run/bloomd.sock"
#define BLOOMD_DEFAULT_PIN_ROOT "/sys/fs/bpf/bloomd"
#define BLOOMD_DEFAULT_META_ROOT "/var/lib/bloomd"
#define BLOOMD_DEFAULT_SOCKET_MODE 0666
#define BLOOMD_BACKEND_NAME "bpf_bloom"
#define BLOOMD_DIGEST_NAME "siphash128-v1"
#define BLOOMD_LOG_SYNC_INTERVAL_MS 250U
#define BLOOMD_LOG_BUFFER_CAP (64U * BLOOMD_DIGEST_SIZE)
#define BLOOMD_VERSION "1.0.0"
#define BLOOMD_FILTER_STATE_DURABLE 0x01U
#define BLOOMD_FILTER_STATE_METADATA_ONLY 0x02U
#define BLOOMD_FILTER_STATE_LOG_CLEAN 0x04U
#define BLOOMD_FILTER_STATE_LOG_DIRTY 0x08U

enum bloomd_opcode {
    BLOOMD_OP_PING = 1,
    BLOOMD_OP_CREATE = 2,
    BLOOMD_OP_ADD = 3,
    BLOOMD_OP_CHECK = 4,
    BLOOMD_OP_MADD = 5,
    BLOOMD_OP_MCHECK = 6,
    BLOOMD_OP_INFO = 7,
    BLOOMD_OP_LIST = 8,
    BLOOMD_OP_DROP = 9,
    BLOOMD_OP_STATS = 10
};

enum bloomd_status {
    BLOOMD_STATUS_OK = 0,
    BLOOMD_STATUS_BAD_REQUEST = 1,
    BLOOMD_STATUS_TOO_LARGE = 2,
    BLOOMD_STATUS_NOT_FOUND = 3,
    BLOOMD_STATUS_EXISTS = 4,
    BLOOMD_STATUS_UNSUPPORTED = 5,
    BLOOMD_STATUS_IO = 6,
    BLOOMD_STATUS_BPF = 7,
    BLOOMD_STATUS_NAME = 8,
    BLOOMD_STATUS_STATE = 9,
    BLOOMD_STATUS_PERM = 10,
    BLOOMD_STATUS_INTERNAL = 11
};

enum bloomd_error_code {
    BLOOMD_ERR_NONE = 0,
    BLOOMD_ERR_PARSE = 1,
    BLOOMD_ERR_RANGE = 2,
    BLOOMD_ERR_TIMEOUT = 3,
    BLOOMD_ERR_SHORT_IO = 4,
    BLOOMD_ERR_UNSUPPORTED_KERNEL = 5,
    BLOOMD_ERR_BPF_PRIVS = 6,
    BLOOMD_ERR_BPFFS = 7,
    BLOOMD_ERR_METADATA = 8
};

enum bloomd_log_sync_mode {
    BLOOMD_LOG_SYNC_PERIODIC = 0,
    BLOOMD_LOG_SYNC_ALWAYS = 1
};

struct bloomd_frame_header {
    uint8_t magic[4];
    uint8_t version;
    uint8_t opcode;
    uint8_t flags;
    uint8_t status;
    uint32_t request_id;
    uint32_t body_len;
} __attribute__((packed));

struct bloomd_create_request {
    uint64_t capacity;
    double error_rate;
    uint32_t hashes;
    uint16_t name_len;
    uint16_t reserved;
};

struct bloomd_name_request {
    uint16_t name_len;
    uint16_t reserved0;
    uint32_t reserved1;
};

struct bloomd_payload_request {
    uint16_t name_len;
    uint16_t reserved0;
    uint32_t payload_len;
};

struct bloomd_batch_request {
    uint16_t name_len;
    uint16_t item_count;
    uint32_t reserved;
};

struct bloomd_error_response {
    uint32_t code;
    uint32_t message_len;
};

struct bloomd_filter_meta {
    char name[BLOOMD_MAX_NAME_LEN + 1];
    char backend[16];
    char digest[32];
    char pin_path[PATH_MAX];
    char meta_path[PATH_MAX];
    char log_path[PATH_MAX];
    uint64_t capacity;
    double error_rate;
    uint32_t hashes;
    uint32_t value_size;
    uint32_t metadata_version;
    bool has_data;
    bool log_clean;
};

struct bloomd_bpf_map_info {
    uint32_t type;
    uint32_t key_size;
    uint32_t value_size;
    uint32_t max_entries;
    uint64_t map_extra;
};

struct bloomd_filter {
    struct bloomd_filter_meta meta;
    int map_fd;
    int log_fd;
    uint8_t log_buf[BLOOMD_LOG_BUFFER_CAP];
    size_t log_buf_len;
    bool log_dirty;
    uint64_t last_log_sync_ms;
    uint64_t add_calls;
    uint64_t check_calls;
    uint64_t batch_add_calls;
    uint64_t batch_check_calls;
};

struct bloomd_stats {
    uint64_t requests;
    uint64_t responses;
    uint64_t errors;
    uint64_t accepted_connections;
    uint64_t filters_loaded;
    uint64_t filters_created;
    uint64_t filters_dropped;
    uint64_t orphan_meta;
    uint64_t orphan_pin;
    uint64_t empty_pool_hits;
    uint64_t empty_pool_misses;
};

struct bloomd_config {
    char socket_path[PATH_MAX];
    char pin_root[PATH_MAX];
    char meta_root[PATH_MAX];
    mode_t socket_mode;
    enum bloomd_log_sync_mode log_sync_mode;
    bool foreground;
    bool fail_if_unsupported;
};

struct bloomd_buffer {
    uint8_t *data;
    size_t len;
    size_t cap;
};

struct bloomd_filter_set {
    struct bloomd_filter *items;
    size_t len;
    size_t cap;
    size_t last_index;
};

struct bloomd_request_view {
    struct bloomd_frame_header header;
    const uint8_t *body;
};

struct bloomd_response {
    struct bloomd_frame_header header;
    struct bloomd_buffer body;
};

void bloomd_config_defaults(struct bloomd_config *cfg);
const char *bloomd_status_string(uint8_t status);
const char *bloomd_errno_string(int code);

bool bloomd_name_is_valid(const char *name);
int bloomd_validate_filter_name(const char *name, char *errbuf, size_t errcap);
int bloomd_build_pin_path(const char *root, const char *name, char *out, size_t out_sz);
int bloomd_build_meta_path(const char *root, const char *name, char *out, size_t out_sz);
int bloomd_build_log_path(const char *root, const char *name, char *out, size_t out_sz);
int bloomd_ensure_dir(const char *path, mode_t mode, bool allow_existing);
bool bloomd_is_bpffs(const char *path);
int bloomd_write_all(int fd, const void *buf, size_t len);
int bloomd_read_all(int fd, void *buf, size_t len);
int bloomd_set_socket_timeouts(int fd, int timeout_ms);
int bloomd_parse_octal_mode(const char *text, mode_t *mode_out);
int bloomd_parse_log_sync_mode(const char *text, enum bloomd_log_sync_mode *mode_out);
uint32_t bloomd_hashes_for_error_rate(double error_rate);
int bloomd_remove_path_if_exists(const char *path);
int bloomd_list_dir(const char *path, char ***names_out, size_t *count_out);
void bloomd_free_name_list(char **names, size_t count);

void bloomd_digest_payload(const void *data, size_t len, uint8_t out[BLOOMD_DIGEST_SIZE]);

void bloomd_buffer_init(struct bloomd_buffer *buf);
void bloomd_buffer_free(struct bloomd_buffer *buf);
int bloomd_buffer_reserve(struct bloomd_buffer *buf, size_t cap);
int bloomd_buffer_append(struct bloomd_buffer *buf, const void *data, size_t len);
int bloomd_buffer_append_u16(struct bloomd_buffer *buf, uint16_t value);
int bloomd_buffer_append_u32(struct bloomd_buffer *buf, uint32_t value);
int bloomd_buffer_append_u64(struct bloomd_buffer *buf, uint64_t value);
int bloomd_buffer_append_double(struct bloomd_buffer *buf, double value);
int bloomd_buffer_append_str(struct bloomd_buffer *buf, const char *str);

int bloomd_read_frame(int fd, struct bloomd_request_view *req, struct bloomd_buffer *storage);
int bloomd_write_response(int fd, const struct bloomd_response *resp);
void bloomd_response_init(struct bloomd_response *resp, uint8_t opcode, uint32_t request_id);
void bloomd_response_reset(struct bloomd_response *resp, uint8_t opcode, uint32_t request_id);
void bloomd_response_free(struct bloomd_response *resp);
int bloomd_response_error(struct bloomd_response *resp, uint8_t status, uint32_t code,
                          const char *message);
int bloomd_protocol_read_name(const uint8_t *buf, size_t len, const char **name, uint16_t *name_len,
                              size_t *consumed);
int bloomd_protocol_read_payload(const uint8_t *buf, size_t len, const uint8_t **payload,
                                 uint32_t *payload_len, size_t *consumed);
uint16_t bloomd_load_u16(const void *src);
uint32_t bloomd_load_u32(const void *src);
uint64_t bloomd_load_u64(const void *src);
double bloomd_load_double(const void *src);

int bloomd_meta_write_atomic(const struct bloomd_filter_meta *meta);
int bloomd_meta_read_file(const char *path, struct bloomd_filter_meta *meta);
int bloomd_meta_delete(const char *path);
int bloomd_meta_recover_stale(const char *path);

typedef int (*bloomd_log_replay_cb)(const uint8_t digest[BLOOMD_DIGEST_SIZE], void *ctx);
int bloomd_log_reset(const char *path);
int bloomd_log_open_append(const char *path);
int bloomd_log_open_create(const char *path);
int bloomd_log_append_fd(int fd, const uint8_t digest[BLOOMD_DIGEST_SIZE]);
int bloomd_log_buffer_append(int fd, uint8_t buf[BLOOMD_LOG_BUFFER_CAP], size_t *buf_len_io,
                             const uint8_t digest[BLOOMD_DIGEST_SIZE]);
int bloomd_log_buffer_flush(int fd, uint8_t buf[BLOOMD_LOG_BUFFER_CAP], size_t *buf_len_io,
                            bool sync);
int bloomd_log_sync(int fd);
int bloomd_log_truncate(int fd, off_t length, bool sync);
void bloomd_log_close(int *fd, bool sync);
int bloomd_log_replay(const char *path, bloomd_log_replay_cb cb, void *ctx, uint64_t *count_out);
int bloomd_log_replay_readonly(const char *path, bloomd_log_replay_cb cb, void *ctx,
                               uint64_t *count_out);
int bloomd_log_delete(const char *path);

int bloomd_bpf_probe_support(char *errbuf, size_t errcap);
int bloomd_bpf_open_pinned(const char *path);
int bloomd_bpf_create_map(const char *name, uint64_t capacity, uint32_t hashes, int *fd_out,
                          char *errbuf, size_t errcap);
int bloomd_bpf_pin_map(int fd, const char *path, char *errbuf, size_t errcap);
int bloomd_bpf_add_digest(int fd, const uint8_t digest[BLOOMD_DIGEST_SIZE], char *errbuf,
                          size_t errcap);
int bloomd_bpf_check_digest(int fd, const uint8_t digest[BLOOMD_DIGEST_SIZE], bool *present_out,
                            char *errbuf, size_t errcap);
int bloomd_bpf_get_map_info(int fd, struct bloomd_bpf_map_info *info_out, char *errbuf, size_t errcap);
int bloomd_bpf_unpin(const char *path, char *errbuf, size_t errcap);
void bloomd_bpf_close(int *fd);
void bloomd_bpf_set_mock_syscall(long (*fn)(int cmd, void *attr, unsigned int size));
void bloomd_bpf_reset_mock_syscall(void);

void bloomd_filter_set_init(struct bloomd_filter_set *set);
void bloomd_filter_set_free(struct bloomd_filter_set *set);
struct bloomd_filter *bloomd_filter_set_find(struct bloomd_filter_set *set, const char *name);
struct bloomd_filter *bloomd_filter_set_find_n(struct bloomd_filter_set *set, const char *name,
                                               size_t name_len);
int bloomd_filter_set_add(struct bloomd_filter_set *set, const struct bloomd_filter *filter);
int bloomd_filter_set_remove(struct bloomd_filter_set *set, const char *name);
int bloomd_filter_set_remove_n(struct bloomd_filter_set *set, const char *name, size_t name_len);

#endif
