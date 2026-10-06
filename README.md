# eBPF System Call Tracer

A lightweight system call tracer written in C using `libbpf` and kernel tracepoints. It tracks execution latency, return codes, and file path arguments for specific target commands.

## Features

- **Command Filtering**: Targets processes by executable name.
- **Latency Tracking**: Measures execution time in microseconds using kernel monotonic clocks.
- **Argument Inspection**: Extracts file paths from user space.
- **Return Value Logging**: Captures system call success/failure status codes.

## Requirements

- Linux kernel with BTF support
- `clang`, `llvm`, `libbpf`, `bpftool`, and kernel headers

## Build & Run

```bash
 make

 sudo ./loader ls
```
