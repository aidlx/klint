# klint

A Linux kernel integrity scanner that detects rootkits and kernel-level
compromises. It works by cross-referencing multiple sources of system
information (procfs, sysfs, netlink, MSRs, IDT, kernel symbols) and flagging
inconsistencies that indicate tampering.

## Features

- **Hidden kernel module detection** -- compares `/proc/modules`,
  `/proc/kallsyms`, and `/sys/module` to find modules concealed from one or
  more views.
- **Hidden process detection** -- probes PID space with `kill(0)` and
  cross-checks against `/proc` readdir and cgroup trees to identify processes
  hidden from directory listings.
- **Hidden network socket detection** -- cross-references `/proc/net`, `ss`
  (netlink), and `/proc/*/fd` to find sockets missing from any single view.
- **Syscall table integrity** -- reads the syscall table from `/proc/kcore` and
  verifies that every entry points into kernel text, catching inline hooks and
  table overwrites.
- **Kernel entrypoint integrity** (x86_64) -- reads MSRs (`IA32_LSTAR`,
  `IA32_CSTAR`, `IA32_SYSENTER_EIP`) and IDT vectors, then validates that
  entrypoints have not been redirected to module code or trampolines.
- **Ftrace redirection detection** -- scans ftrace filter lists for hooks on
  security-critical kernel functions (35 built-in patterns covering syscall
  dispatch, VFS, credential, and networking paths).
- **Unknown kprobe detection** -- inspects registered kprobe and kretprobe
  events for probes targeting sensitive kernel symbols.
- **BPF rootkit detection** -- inventories loaded BPF programs, maps, and links
  via `bpftool`, flagging ownerless or high-risk programs attached to sensitive
  hooks.

Each scanner runs in an isolated child process with a configurable timeout
(default 30 seconds), communicating results back via JSON over a pipe. A
dual-snapshot reconciliation strategy distinguishes transient anomalies from
persistent ones.

## Requirements

- Linux (x86_64 for full coverage; some scanners are architecture-specific)
- C++23 compiler (GCC 13+ or Clang 17+)
- CMake 3.28+
- [nlohmann/json](https://github.com/nlohmann/json)
- Root privileges at runtime

Optional external tools used by specific scanners:

| Tool      | Scanner                    |
|-----------|----------------------------|
| `ss`      | `hidden_network_sockets`   |
| `bpftool` | `bpf_rootkit_detection`    |

Scanners that require a missing tool are automatically skipped.

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

The binary is produced at `build/klint`.

### Build options

| Option              | Default | Description                              |
|---------------------|---------|------------------------------------------|
| `STATIC_BUILD`      | OFF     | Produce a fully static binary            |
| `ENABLE_SANITIZERS` | OFF     | Enable AddressSanitizer and UBSanitizer  |
| `WERROR`            | OFF     | Treat compiler warnings as errors        |

Example for a static build:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSTATIC_BUILD=ON
cmake --build build
```

## Usage

```
klint [options]
```

klint must be run as root.

```sh
sudo ./build/klint                # run all scanners, text output
sudo ./build/klint --json         # run all scanners, JSON output
sudo ./build/klint --list         # list available scanners and exit
```

### Options

```
--json               Emit JSON output
--text               Emit colored text output (default)
--scanner <name>     Run only the named scanner (repeatable)
--exclude <name>     Skip the named scanner (repeatable, overrides --scanner)
--list               List available scanners and exit
--timeout <seconds>  Per-scanner timeout in seconds (default: 30)
--no-color           Disable ANSI color codes
-h, --help           Show help and exit
```

Color output is automatically disabled when stdout is not a TTY or when the
`NO_COLOR` environment variable is set.

### Examples

Run only the hidden process and hidden LKM scanners:

```sh
sudo ./build/klint --scanner hidden_processes --scanner hidden_lkm
```

Run all scanners except BPF detection with a 60-second timeout:

```sh
sudo ./build/klint --exclude bpf_rootkit_detection --timeout 60
```

Produce machine-readable output for ingestion by other tools:

```sh
sudo ./build/klint --json > report.json
```

## Scanners

| Scanner                        | Category | External tools | Description                                            |
|--------------------------------|----------|----------------|--------------------------------------------------------|
| `hidden_lkm`                  | kernel   | --             | Detects kernel modules hidden from /proc or /sys       |
| `hidden_processes`            | process  | --             | Detects processes hidden from /proc directory listings  |
| `hidden_network_sockets`      | network  | `ss`           | Detects sockets hidden from /proc/net                  |
| `syscall_table_integrity`     | kernel   | --             | Validates syscall table entries point to kernel text    |
| `kernel_entrypoint_integrity` | kernel   | --             | Validates MSR and IDT syscall entrypoints (x86_64)     |
| `ftrace_redirection`          | kernel   | --             | Detects ftrace hooks on critical kernel functions       |
| `unknown_kprobes`             | kernel   | --             | Detects kprobes targeting sensitive kernel symbols      |
| `bpf_rootkit_detection`       | kernel   | `bpftool`      | Detects suspicious or ownerless BPF programs           |

## Severity levels

Findings are reported at one of three severity levels:

- **critical** -- high confidence that the system has been compromised.
- **warning** -- suspicious activity that could be benign (e.g., legitimate
  security tooling) but warrants investigation.
- **info** -- supplementary context that does not indicate compromise on its own.

## Exit codes

| Code | Meaning                                    |
|------|--------------------------------------------|
| 0    | All scanners passed with no findings       |
| 1    | One or more findings at warning or above   |
| 2    | Errors, timeouts, or invalid usage         |

## Project structure

```
src/
  main.cpp                            Entry point and scanner orchestration
  cli.cpp / cli.hpp                   Command-line argument parsing
  color.hpp                           ANSI color output
  result.hpp                          Finding, ScanResult, Severity types
  scanner.hpp                         Scanner registry framework
  output.cpp / output.hpp             Text and JSON report formatting
  util.cpp / util.hpp                 File I/O, command execution, utilities
  kcore_reader.cpp / kcore_reader.hpp /proc/kcore ELF parser
  critical_kernel_patterns.hpp        Sensitive kernel symbol patterns
  scanners/
    hidden_lkm.cpp
    hidden_processes.cpp
    hidden_network_sockets.cpp
    syscall_table_integrity.cpp
    kernel_entrypoint_integrity.cpp
    ftrace_redirection.cpp
    unknown_kprobes.cpp
    bpf_rootkit_detection.cpp
```

## How it works

klint relies on the principle that rootkits must hide from at least one view of
the system to be effective, but rarely hide from all views simultaneously. By
comparing information from independent kernel interfaces -- procfs, sysfs,
netlink sockets, MSRs, the IDT, `/proc/kcore`, and direct syscalls -- klint
identifies discrepancies that reveal tampering.

Each scanner runs in a separate child process group. If a scanner hangs (as can
happen when interacting with a compromised kernel), it is killed after the
timeout expires. Results are serialized as JSON over a pipe back to the parent,
which assembles the final report.

Symbol resolution uses `/proc/kallsyms` with automatic KASLR slide detection
via anchor symbols, falling back to `System.map` when needed.
