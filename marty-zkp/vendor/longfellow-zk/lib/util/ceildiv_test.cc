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

#include "util/ceildiv.h"

#include <cstddef>
#include <cstdint>

#include "gtest/gtest.h"

namespace proofs {
namespace morton {
namespace {

static uint64_t bit(uint64_t x) { return x & 1u; }
static uint64_t naive_even(uint64_t x) {
  uint64_t r = 0;
  for (size_t i = 0; i < 32; ++i) {
    r |= bit(x >> (2 * i)) << i;
  }
  return r;
}

static uint64_t naive_uneven(uint64_t x) {
  uint64_t r = 0;
  for (size_t i = 0; i < 32; ++i) {
    r |= bit(x >> i) << (2 * i);
  }
  return r;
}

TEST(Morton, Even) {
  // small integers
  for (uint64_t x = 0; x < 8192; ++x) {
    EXPECT_EQ(naive_even(x), morton::even(x));
  }

  // powers of two and neighbors
  for (uint64_t x = 1; x != 0; x *= 2) {
    EXPECT_EQ(naive_even(x - 1), morton::even(x - 1));
    EXPECT_EQ(naive_even(x), morton::even(x));
    EXPECT_EQ(naive_even(x + 1), morton::even(x + 1));
  }

  // semi-random
  for (uint64_t x = 0; x < 8192; ++x) {
    uint64_t y = x * 0xdeadbeefabadcafeull;
    EXPECT_EQ(naive_even(y - 1), morton::even(y - 1));
    EXPECT_EQ(naive_even(y), morton::even(y));
    EXPECT_EQ(naive_even(y + 1), morton::even(y + 1));
  }
}

TEST(Morton, Uneven) {
  // small integers
  for (uint64_t x = 0; x < 8192; ++x) {
    EXPECT_EQ(naive_uneven(x), morton::uneven(x));
  }

  // powers of two and neighbors
  for (uint64_t x = 1; x != 0; x *= 2) {
    EXPECT_EQ(naive_uneven(x - 1), morton::uneven(x - 1));
    EXPECT_EQ(naive_uneven(x), morton::uneven(x));
    EXPECT_EQ(naive_uneven(x + 1), morton::uneven(x + 1));
  }

  // semi-random
  for (uint64_t x = 0; x < 8192; ++x) {
    uint64_t y = x * 0xdeadbeefabadcafeull;
    EXPECT_EQ(naive_uneven(y - 1), morton::uneven(y - 1));
    EXPECT_EQ(naive_uneven(y), morton::uneven(y));
    EXPECT_EQ(naive_uneven(y + 1), morton::uneven(y + 1));
  }
}

static void one_add_test(uint64_t x, uint64_t y) {
  uint32_t x0 = morton::even(x), x1 = morton::even(x >> 1);
  uint32_t y0 = morton::even(y), y1 = morton::even(y >> 1);
  morton::add<uint32_t>(&x0, &x1, y0, y1);
  uint64_t r = morton::uneven(x0) | (morton::uneven(x1) << 1);
  EXPECT_EQ(r, x + y);
}

static void one_sub_test(uint64_t x, uint64_t y) {
  uint32_t x0 = morton::even(x), x1 = morton::even(x >> 1);
  uint32_t y0 = morton::even(y), y1 = morton::even(y >> 1);
  morton::sub<uint32_t>(&x0, &x1, y0, y1);
  uint64_t r = morton::uneven(x0) | (morton::uneven(x1) << 1);
  EXPECT_EQ(r, x - y);
}

static void one_lt_test(uint64_t x, uint64_t y) {
  uint32_t x0 = morton::even(x), x1 = morton::even(x >> 1);
  uint32_t y0 = morton::even(y), y1 = morton::even(y >> 1);
  bool lt = morton::lt<uint32_t>(x0, x1, y0, y1);
  // Define x < y as the sign bit of the subtraction.
  // We could cast to int64_t but signed overflow is
  // undefined behavior.
  EXPECT_EQ(lt, (((x - y) >> 63) == 1));
}

static void one_eq_test(uint64_t x, uint64_t y) {
  uint32_t x0 = morton::even(x), x1 = morton::even(x >> 1);
  uint32_t y0 = morton::even(y), y1 = morton::even(y >> 1);
  bool eq = morton::eq<uint32_t>(x0, x1, y0, y1);
  // Define x < y as the sign bit of the subtraction.
  // We could cast to int64_t but signed overflow is
  // undefined behavior.
  EXPECT_EQ(eq, x == y);
}

static void one_test(uint64_t x, uint64_t y) {
  one_add_test(x, y);
  one_sub_test(x, y);
  one_lt_test(x, y);
  one_eq_test(x, y);
}

TEST(Morton, AddSub) {
  // small integers
  for (size_t x = 0; x < 256; ++x) {
    for (size_t y = 0; y < 256; ++y) {
      one_test(x, y);
    }
  }

  // powers of two plus delta
  for (size_t x = 1; x; x *= 2) {
    for (size_t y = 1; y; y *= 2) {
      for (int dx = -16; dx < 16; ++dx) {
        for (int dy = -16; dy < 16; ++dy) {
          one_test(x + dx, y + dx);
        }
      }
    }
  }
}

}  // namespace
}  // namespace morton
}  // namespace proofs
