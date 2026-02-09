#pragma once

#include <array>
#include <string_view>

namespace klint::patterns {

enum class MatchKind {
  Prefix,
  Contains,
  Exact,
};

struct CriticalPattern {
  std::string_view tag;
  std::string_view pattern;
  MatchKind kind;
};

inline constexpr std::array<CriticalPattern, 35> kCriticalKernelPatterns = {{
    {"syscall", "__x64_sys_", MatchKind::Prefix},
    {"syscall", "__ia32_sys_", MatchKind::Prefix},
    {"syscall", "__arm64_sys_", MatchKind::Prefix},
    {"syscall", "__se_sys_", MatchKind::Prefix},
    {"syscall", "sys_", MatchKind::Prefix},
    {"syscall", "do_sys_", MatchKind::Prefix},
    {"cred", "commit_creds", MatchKind::Exact},
    {"cred", "prepare_kernel_cred", MatchKind::Exact},
    {"lsm", "security_", MatchKind::Prefix},
    {"module", "load_module", MatchKind::Prefix},
    {"module", "do_init_module", MatchKind::Prefix},
    {"module", "__x64_sys_init_module", MatchKind::Prefix},
    {"module", "__x64_sys_finit_module", MatchKind::Prefix},
    {"module", "sys_init_module", MatchKind::Prefix},
    {"module", "sys_finit_module", MatchKind::Prefix},
    {"module", "module_", MatchKind::Prefix},
    {"bpf", "__x64_sys_bpf", MatchKind::Prefix},
    {"bpf", "sys_bpf", MatchKind::Prefix},
    {"bpf", "bpf_prog_", MatchKind::Prefix},
    {"bpf", "bpf_map_", MatchKind::Prefix},
    {"exec", "do_execve", MatchKind::Prefix},
    {"exec", "__x64_sys_execve", MatchKind::Prefix},
    {"exec", "__x64_sys_execveat", MatchKind::Prefix},
    {"vfs", "vfs_", MatchKind::Prefix},
    {"vfs", "do_filp_open", MatchKind::Prefix},
    {"vfs", "filp_open", MatchKind::Prefix},
    {"vfs", "kern_path", MatchKind::Prefix},
    {"net", "tcp_", MatchKind::Prefix},
    {"net", "udp_", MatchKind::Prefix},
    {"net", "inet_", MatchKind::Prefix},
    {"net", "ip_", MatchKind::Prefix},
    {"proc", "do_fork", MatchKind::Prefix},
    {"proc", "kernel_clone", MatchKind::Prefix},
    {"proc", "do_exit", MatchKind::Prefix},
    {"proc", "exit_group", MatchKind::Prefix},
}};

} // namespace klint::patterns
