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

#include "algebra/limb.h"

#include <array>
#include <cstdint>
#include <cstdlib>

#include "gtest/gtest.h"

namespace proofs {
namespace {
TEST(Limb, Scalar) {
  constexpr size_t W = 4;
  Limb<W> k42 = Limb<W>(42);
  EXPECT_EQ(k42, k42);

  auto k42u64 = k42.u64();
  EXPECT_EQ(k42u64[0], 42u);
  for (size_t i = 1; i < 4; ++i) {
    EXPECT_EQ(k42u64[i], 0u);
  }

  uint8_t bytes[32];
  k42.to_bytes(bytes);
  EXPECT_EQ(bytes[0], 42);
  for (size_t i = 1; i < 32; ++i) {
    EXPECT_EQ(bytes[i], 0u);
  }
}

TEST(Limb, Array) {
  constexpr size_t W = 4;
  std::array<uint64_t, W> k = {
      0x0706050403020100ull,
      0x0f0e0d0c0b0a0908ull,
      0x1716151413121110ull,
      0x1f1e1d1c1b1a1918ull,
  };
  Limb<W> kk = Limb<W>(k);
  EXPECT_EQ(kk, kk);

  auto kku64 = kk.u64();
  for (size_t i = 0; i < 4; ++i) {
    EXPECT_EQ(kku64[i], k[i]);
  }

  uint8_t bytes[32];
  kk.to_bytes(bytes);
  for (size_t i = 0; i < 32; ++i) {
    EXPECT_EQ(bytes[i], i);
  }

  kk.shiftr(8);
  kk.to_bytes(bytes);
  for (size_t i = 0; i < 31; ++i) {
    EXPECT_EQ(bytes[i], i + 1);
  }
  EXPECT_EQ(bytes[31], 0u);
}

TEST(Limb, Bit) {
  constexpr size_t W = 4;
  std::array<uint64_t, W> k = {1, 0, 0, 0};
  Limb<W> kk(k);
  EXPECT_EQ(kk.bit(0), 1);
  EXPECT_EQ(kk.bit(1), 0);
  EXPECT_EQ(kk.bit(256), 0);
}

}  // namespace
}  // namespace proofs
