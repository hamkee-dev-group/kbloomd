CC := gcc
CFLAGS := -std=c11 -O2 -g -Wall -Wextra -Werror -pedantic -D_GNU_SOURCE -Iinclude
LDFLAGS := -lm

BUILD_DIR := build
SRC_DIR := src

COMMON_SRCS := \
	$(SRC_DIR)/protocol.c \
	$(SRC_DIR)/hash.c \
	$(SRC_DIR)/util.c \
	$(SRC_DIR)/log.c \
	$(SRC_DIR)/meta.c \
	$(SRC_DIR)/bpf.c

DAEMON_SRCS := $(COMMON_SRCS) $(SRC_DIR)/daemon.c
CTL_SRCS := $(COMMON_SRCS) $(SRC_DIR)/bloomctl.c
INSPECT_SRCS := $(COMMON_SRCS) $(SRC_DIR)/bloominspect.c

ALL_BINS := \
	$(BUILD_DIR)/bloomd \
	$(BUILD_DIR)/bloomctl \
	$(BUILD_DIR)/bloominspect

CPPHECK_DIRS := $(SRC_DIR) include

.PHONY: all clean lint

all: $(ALL_BINS)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/bloomd: $(DAEMON_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(DAEMON_SRCS) $(LDFLAGS)

$(BUILD_DIR)/bloomctl: $(CTL_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(CTL_SRCS) $(LDFLAGS)

$(BUILD_DIR)/bloominspect: $(INSPECT_SRCS) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(INSPECT_SRCS) $(LDFLAGS)

lint:
	cppcheck --enable=warning,performance,portability --error-exitcode=1 --quiet --check-level=exhaustive --std=c11 -Iinclude --suppress=missingIncludeSystem $(CPPHECK_DIRS)

clean:
	rm -rf $(BUILD_DIR)
