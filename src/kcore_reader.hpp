#pragma once

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace klint::kcore {

struct Segment {
  std::uint64_t vaddr = 0;
  std::uint64_t memsz = 0;
  std::uint64_t offset = 0;
  std::uint64_t filesz = 0;
  std::uint32_t flags = 0;
};

struct KcoreImage {
  int fd = -1;
  std::size_t ptr_size = 0;
  std::vector<Segment> segments;

  KcoreImage() = default;
  KcoreImage(const KcoreImage &) = delete;
  KcoreImage &operator=(const KcoreImage &) = delete;
  KcoreImage(KcoreImage &&other) noexcept;
  KcoreImage &operator=(KcoreImage &&other) noexcept;
  ~KcoreImage();
};

std::expected<KcoreImage, std::string> load_kcore();

std::optional<std::vector<std::uint8_t>>
read_kcore_range(const KcoreImage &image, std::uint64_t addr, std::size_t len);

std::uint64_t read_le(const std::uint8_t *data, std::size_t size);

} // namespace klint::kcore
