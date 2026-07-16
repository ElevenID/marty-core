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

#include "algebra/sysdep.h"

#include <cstdint>

#include "gtest/gtest.h"

namespace proofs {
namespace {
#ifndef SYSDEP_MULQ64_NOT_DEFINED
TEST(Sysdep, mulhl64) {
  uint64_t l, h;
  uint64_t b = (1ull << 47) + 1u;
  mulhl(1, &l, &h, (static_cast<uint64_t>(1) << 53) + 1u, &b);
  EXPECT_EQ(l, 1 + (1ull << 53) + (1ull << 47));
  EXPECT_EQ(h, 1ull << (53 + 47 - 64));
}
#endif

TEST(Sysdep, mulhl32) {
  uint32_t l, h;
  uint32_t b = (1ull << 29) + 1u;
  mulhl(1, &l, &h, (static_cast<uint32_t>(1) << 27) + 1u, &b);
  EXPECT_EQ(l, 1 + (1ull << 27) + (1ull << 29));
  EXPECT_EQ(h, 1ull << (27 + 29 - 32));
}
TEST(Sysdep, cmovnz) {
  uint64_t a[1] = {1};
  uint64_t b[1] = {2};
  cmovnz(1, a, 0, b);
  EXPECT_EQ(a[0], 1);
  cmovnz(1, a, 1, b);
  EXPECT_EQ(a[0], 2);
}
}  // namespace
}  // namespace proofs
