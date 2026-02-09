#include "kcore_reader.hpp"

#include <elf.h>
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <utility>

namespace klint::kcore {

namespace {

std::string errno_message(const std::string &prefix) {
  return prefix + ": " + std::strerror(errno);
}

bool read_exact(int fd, void *buffer, std::size_t len, std::uint64_t offset) {
  std::size_t read_total = 0;
  auto *out = static_cast<std::uint8_t *>(buffer);
  while (read_total < len) {
    ssize_t n = ::pread(fd, out + read_total, len - read_total,
                        static_cast<off_t>(offset + read_total));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return false;
    }
    if (n == 0) {
      return false;
    }
    read_total += static_cast<std::size_t>(n);
  }
  return true;
}

} // namespace

KcoreImage::KcoreImage(KcoreImage &&other) noexcept
    : fd(other.fd), ptr_size(other.ptr_size),
      segments(std::move(other.segments)) {
  other.fd = -1;
}

KcoreImage &KcoreImage::operator=(KcoreImage &&other) noexcept {
  if (this != &other) {
    if (fd != -1) {
      ::close(fd);
    }
    fd = other.fd;
    ptr_size = other.ptr_size;
    segments = std::move(other.segments);
    other.fd = -1;
  }
  return *this;
}

KcoreImage::~KcoreImage() {
  if (fd != -1) {
    ::close(fd);
  }
}

std::expected<KcoreImage, std::string> load_kcore() {
  int fd = ::open("/proc/kcore", O_RDONLY | O_CLOEXEC);
  if (fd == -1) {
    return std::unexpected(errno_message("open /proc/kcore"));
  }

  unsigned char ident[EI_NIDENT];
  if (!read_exact(fd, ident, sizeof(ident), 0)) {
    ::close(fd);
    return std::unexpected("read /proc/kcore header failed");
  }

  if (std::memcmp(ident, ELFMAG, SELFMAG) != 0) {
    ::close(fd);
    return std::unexpected("/proc/kcore is not an ELF core file");
  }

  if (ident[EI_DATA] != ELFDATA2LSB) {
    ::close(fd);
    return std::unexpected("/proc/kcore has unsupported endianness");
  }

  KcoreImage image;
  image.fd = fd;

  if (ident[EI_CLASS] == ELFCLASS64) {
    Elf64_Ehdr header{};
    if (!read_exact(fd, &header, sizeof(header), 0)) {
      return std::unexpected("read /proc/kcore ELF64 header failed");
    }

    if (header.e_phentsize != sizeof(Elf64_Phdr)) {
      return std::unexpected(
          "unexpected ELF64 program header size in /proc/kcore");
    }

    image.ptr_size = 8;
    for (std::size_t i = 0; i < header.e_phnum; ++i) {
      Elf64_Phdr phdr{};
      std::uint64_t offset =
          header.e_phoff + i * static_cast<std::uint64_t>(header.e_phentsize);
      if (!read_exact(fd, &phdr, sizeof(phdr), offset)) {
        return std::unexpected("read /proc/kcore program header failed");
      }
      if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0 || phdr.p_filesz == 0) {
        continue;
      }
      image.segments.push_back(Segment{
          .vaddr = phdr.p_vaddr,
          .memsz = phdr.p_memsz,
          .offset = phdr.p_offset,
          .filesz = phdr.p_filesz,
          .flags = phdr.p_flags,
      });
    }
  } else if (ident[EI_CLASS] == ELFCLASS32) {
    Elf32_Ehdr header{};
    if (!read_exact(fd, &header, sizeof(header), 0)) {
      return std::unexpected("read /proc/kcore ELF32 header failed");
    }

    if (header.e_phentsize != sizeof(Elf32_Phdr)) {
      return std::unexpected(
          "unexpected ELF32 program header size in /proc/kcore");
    }

    image.ptr_size = 4;
    for (std::size_t i = 0; i < header.e_phnum; ++i) {
      Elf32_Phdr phdr{};
      std::uint64_t offset =
          header.e_phoff + i * static_cast<std::uint64_t>(header.e_phentsize);
      if (!read_exact(fd, &phdr, sizeof(phdr), offset)) {
        return std::unexpected("read /proc/kcore program header failed");
      }
      if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0 || phdr.p_filesz == 0) {
        continue;
      }
      image.segments.push_back(Segment{
          .vaddr = phdr.p_vaddr,
          .memsz = phdr.p_memsz,
          .offset = phdr.p_offset,
          .filesz = phdr.p_filesz,
          .flags = phdr.p_flags,
      });
    }
  } else {
    return std::unexpected("/proc/kcore has unsupported ELF class");
  }

  if (image.segments.empty()) {
    return std::unexpected("/proc/kcore has no loadable segments");
  }

  return image;
}

std::optional<std::vector<std::uint8_t>>
read_kcore_range(const KcoreImage &image, std::uint64_t addr, std::size_t len) {
  if (len == 0) {
    return std::vector<std::uint8_t>{};
  }

  std::vector<std::uint8_t> buffer(len);
  std::size_t copied = 0;
  std::uint64_t current = addr;

  while (copied < len) {
    const Segment *segment = nullptr;
    for (const auto &seg : image.segments) {
      if (current >= seg.vaddr && current < seg.vaddr + seg.memsz) {
        segment = &seg;
        break;
      }
    }

    if (!segment) {
      return std::nullopt;
    }

    std::uint64_t seg_offset = current - segment->vaddr;
    std::uint64_t seg_available = segment->memsz - seg_offset;
    if (segment->filesz > seg_offset) {
      seg_available =
          std::min<std::uint64_t>(seg_available, segment->filesz - seg_offset);
    } else {
      return std::nullopt;
    }

    std::size_t chunk = static_cast<std::size_t>(
        std::min<std::uint64_t>(seg_available, len - copied));
    if (chunk == 0) {
      return std::nullopt;
    }

    if (!read_exact(image.fd, buffer.data() + copied, chunk,
                    segment->offset + seg_offset)) {
      return std::nullopt;
    }

    copied += chunk;
    current += chunk;
  }

  return buffer;
}

std::uint64_t read_le(const std::uint8_t *data, std::size_t size) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < size; ++i) {
    value |= static_cast<std::uint64_t>(data[i]) << (8 * i);
  }
  return value;
}

} // namespace klint::kcore
