# bloomd

`bloomd` is a small Linux daemon for local Bloom filters.

It uses the kernel `BPF_MAP_TYPE_BLOOM_FILTER` backend directly, exposes a
Unix-domain socket for local clients, and keeps filter state on disk so filters
can survive restarts and be rebuilt if a pinned map disappears.

## What it does

- Runs as a local daemon, usually as `root`
- Creates and manages Bloom filters backed by the Linux kernel
- Accepts requests over a Unix socket through the included `bloomctl` client
- Stores metadata in `/var/lib/bloomd`
- Pins filters in bpffs under `/sys/fs/bpf/bloomd`
- Keeps an append-only digest log so a missing pinned map can be rebuilt

This project is intentionally narrow in scope: Linux only, local socket only,
single-process, and built around the kernel Bloom filter map.

## Requirements

- Linux 5.16 or later with `BPF_MAP_TYPE_BLOOM_FILTER` available
- bpffs mounted at `/sys/fs/bpf`
- Permission to write `/run/bloomd.sock`, `/var/lib/bloomd`, and `/sys/fs/bpf/bloomd`
- A C11 toolchain and `make`

`bloomd` should be started as `root`, because creating and pinning kernel maps
requires elevated privileges. Local clients do not need root access by default.

## Build

```sh
make
```

This builds:

- `build/bloomd`
- `build/bloomctl`
- `build/bloominspect`

## Run

Start the daemon:

```sh
sudo ./build/bloomd \
  --socket /run/bloomd.sock \
  --pin-root /sys/fs/bpf/bloomd \
  --meta-root /var/lib/bloomd
```

If you want every insert synced to the replay log immediately, add:

```sh
--log-sync-mode always
```

By default, the socket mode is `0666` so unprivileged local callers can connect.
If you want a stricter local policy, set `--socket-mode OCTAL`.

## Basic usage

```sh
./build/bloomctl -s /run/bloomd.sock ping
./build/bloomctl -s /run/bloomd.sock create users 100000 0.001 3
./build/bloomctl -s /run/bloomd.sock add users alice@example.com
./build/bloomctl -s /run/bloomd.sock check users alice@example.com
./build/bloomctl -s /run/bloomd.sock madd users alice bob charlie
./build/bloomctl -s /run/bloomd.sock mcheck users alice bob charlie
./build/bloomctl -s /run/bloomd.sock info users
./build/bloomctl -s /run/bloomd.sock list
./build/bloomctl -s /run/bloomd.sock stats
./build/bloomctl -s /run/bloomd.sock drop users
```

`bloominspect` can be used offline to inspect metadata, pinned filters, and
replay-log health without needing the daemon to be running.

## Persistence and recovery

Each filter uses three pieces of state:

- A pinned kernel Bloom map in `/sys/fs/bpf/bloomd/<name>`
- A metadata file in `/var/lib/bloomd/<name>.meta`
- A digest replay log in `/var/lib/bloomd/<name>.digests`

On startup, `bloomd` scans the metadata and pinned maps, loads valid filters,
and rebuilds missing pinned maps from the digest log when that is safe to do.

## Benchmark results

The current benchmark snapshot compares `bloomd` against Redis with RedisBloom
over Unix sockets on the same machine.

Environment:

- Host kernel: `6.12`
- Compiler: `gcc 14.2.0 (Debian 14.2)`
- Redis: `redis-server v=8.0.2`
- Transport: Unix-domain socket on both sides
- Config: repeats=5, warmups=1, single_iters=20000, batch_items=32768, mixed_iters=40000, control_iters=250, log_sync_mode=periodic

Median of 5 repeats per cell, with 1 warmup. Ratio is `RedisBloom / bloomd`, so
higher means `bloomd` is faster.

| Workload        | bloomd            | RedisBloom        | Ratio |
|-----------------|-------------------|-------------------|-------|
| control cycle   | 145138.6 ns/cycle | 187650.5 ns/cycle | 1.29x |
| single add      | 22426.2 ns/op     | 29498.0 ns/op     | 1.32x |
| single check    | 22405.7 ns/op     | 27807.4 ns/op     | 1.24x |
| batch-8 add     | 4150.3 ns/item    | 7150.1 ns/item    | 1.72x |
| batch-8 check   | 3936.3 ns/item    | 6651.8 ns/item    | 1.69x |
| batch-32 add    | 1541.4 ns/item    | 4609.7 ns/item    | 2.99x |
| batch-32 check  | 1526.0 ns/item    | 4531.7 ns/item    | 2.97x |
| batch-128 add   | 981.0 ns/item     | 4127.5 ns/item    | 4.21x |
| batch-128 check | 933.3 ns/item     | 4082.1 ns/item    | 4.37x |
| mixed 90/10     | 22756.0 ns/op     | 26886.0 ns/op     | 1.18x |

System measurements:

| Metric                    | Value                                         |
|---------------------------|-----------------------------------------------|
| Startup cold              | 73.11 ms                                      |
| Startup restart           | 73.82 ms                                      |
| RSS                       | 7492 kB (~7.3 MB)                             |
| Reconnect median          | 41095.5 ns (~41.1 us)                         |
| Multi-client throughput   | 36477.2 ops/s (4 clients, 8000 ops)           |
| Multi-client p50 / p95    | 90515 ns / 235616 ns                          |
| Control-churn             | 8467.4 cycles/s, p50 443115 ns, p95 655970 ns |
| Filter-scale 1/64/256/512 | 21713 / 23963 / 25468 / 28010 ns              |

In short: `bloomd` is faster than RedisBloom in every measured workload in this
snapshot, with the largest gains showing up on batch operations.

## Installed service

The repository includes:

- [`scripts/install-systemd.sh`](/home/crypto/kbloomd/scripts/install-systemd.sh)
- [`scripts/uninstall-systemd.sh`](/home/crypto/kbloomd/scripts/uninstall-systemd.sh)
- [`systemd/bloomd.service`](/home/crypto/kbloomd/systemd/bloomd.service)

These install the daemon, client tools, and a systemd unit for running
`bloomd` as a local service.
