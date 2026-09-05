// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "circuits/mdoc/mdoc_decompress.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <vector>

#include "util/log.h"
#include "zstd.h"

namespace proofs {

// Decompress a circuit representation into a vector that has been reserved
// with size len.  The value len needs to be a good upper-bound estimate on
// the size of the uncompressed string.
size_t decompress(std::vector<uint8_t>& bytes, const uint8_t* compressed,
                  size_t compressed_len) {
  constexpr unsigned long long kMaxDecompressedCircuitBytes = 130000000;
  const unsigned long long frame_size =
      ZSTD_getFrameContentSize(compressed, compressed_len);
  if (frame_size == ZSTD_CONTENTSIZE_ERROR ||
      frame_size == ZSTD_CONTENTSIZE_UNKNOWN || frame_size == 0 ||
      frame_size > kMaxDecompressedCircuitBytes) {
    log(ERROR, "invalid or excessive circuit frame size: %llu", frame_size);
    return 0;
  }
  try {
    bytes.clear();
    bytes.resize(static_cast<size_t>(frame_size));
  } catch (const std::bad_alloc&) {
    log(ERROR, "circuit allocation failed");
    return 0;
  }
  size_t res =
      ZSTD_decompress(bytes.data(), bytes.size(), compressed, compressed_len);

  if (ZSTD_isError(res)) {
    log(ERROR, "zlib.UncompressAtMost failed: %s", ZSTD_getErrorName(res));
    return 0;
  }
  return res;
}

}  // namespace proofs
