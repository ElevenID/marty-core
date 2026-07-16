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

#include "random/random.h"

#include <stdio.h>
#include <stdlib.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "algebra/fp.h"
#include "algebra/fp24.h"
#include "gf2k/gf2_128.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef Fp<1> Field;
typedef Field::Elt Elt;
static const Field F("18446744069414584321");

static void test_bytes(RandomEngine *e) {
  // check that no bit is stuck at 0 or 1.
  constexpr size_t N = 100;
  uint8_t buf[N];

  e->bytes(buf, N);
  uint8_t band = 0xFFu, bor = 0x00u;
  for (size_t i = 0; i < N; ++i) {
    band &= buf[i];
    bor |= buf[i];
  }
  EXPECT_EQ(band, 0x00u);
  EXPECT_EQ(bor, 0xFFu);
}

static void test_nat(RandomEngine *e, size_t ub) {
  // check that no bit is stuck at 0 or 1.
  constexpr size_t N = 100;

  size_t bor = 0;
  size_t band = ~bor;
  for (size_t i = 0; i < N; ++i) {
    size_t u = e->nat(ub);
    EXPECT_LT(u, ub);
    band &= u;
    bor |= u;
  }
  EXPECT_EQ(band, 0u);
  EXPECT_EQ(bor, e->mask(ub - 1));
}

static void test_elt(RandomEngine *e) {
  // Basic sanity test: Generate an array of elements and check that they
  // are not all the same.  Beware of the birthday paradox.
  constexpr size_t N = 30;
  Elt x[N];
  e->elt(x, N, F);
  for (size_t i = 0; i < N; ++i) {
    for (size_t j = 0; j < N; ++j) {
      if (i != j) {
        // Generated elements in an array shouldn't equal to each other.
        EXPECT_NE(x[i], x[j]);
      }
    }
  }
}

static void test_choose(RandomEngine *e, size_t n, size_t k) {
  std::vector<size_t> r(k);
  e->choose(r.data(), n, k);
  for (size_t i = 0; i < k; ++i) {
    EXPECT_LT(r[i], n);
  }

  // sort the array and check that all elements
  // are distinct
  std::sort(r.begin(), r.end());
  for (size_t i = 1; i < k; ++i) {
    EXPECT_LT(r[i - 1], r[i]);
  }
}

static void test_all(RandomEngine *e) {
  test_bytes(e);
  test_nat(e, 7);
  test_nat(e, 8);
  test_nat(e, 9);
  test_nat(e, (1u << 31) + ((1u << 31) - 1u));
  test_elt(e);
  for (size_t k = 0; k <= 32; ++k) {
    test_choose(e, 32, k);
  }
  test_choose(e, 10000, 42);
  test_choose(e, 10000, 10000);
}

static void test_mask(RandomEngine *e) {
  for (size_t n = 0; n < 1000; ++n) {
    size_t m = e->mask(n);
    EXPECT_TRUE(n == (n & m));
    EXPECT_TRUE((m == 0) || (n != (n & (m >> 1))));
  }
}

TEST(Random, FSPRF) {
  Transcript ts((uint8_t *)"test", 4);
  test_all(&ts);
  test_mask(&ts);
}

TEST(Random, SmallPrime24Bit) {
  // 24-bit prime: 2^24 - 3
  typedef Fp<1> Field24;
  Field24 F("16777213");
  SecureRandomEngine e;
  constexpr size_t N = 100;
  for (size_t i = 0; i < N; ++i) {
    Field24::Elt x = e.elt(F);
    EXPECT_LT(x.n, F.m_);
    x = e.subfield_elt(F);
    EXPECT_LT(x.n, F.m_);
  }
}

TEST(Random, Fp24) {
  // 24-bit prime: 2^24 - 3
  Fp24 F(8380417);
  SecureRandomEngine e;
  constexpr size_t N = 100;
  for (size_t i = 0; i < N; ++i) {
    Fp24::Elt x = e.elt(F);
    EXPECT_LT(x.n, F.m_);
    x = e.subfield_elt(F);
    EXPECT_LT(x.n, F.m_);
  }
}

TEST(Random, LargePrime80Bit) {
  // 80-bit prime: 2^80 - 65
  typedef Fp<2> Field80;
  Field80 F("1208925819614629174706111");
  SecureRandomEngine e;
  constexpr size_t N = 100;
  for (size_t i = 0; i < N; ++i) {
    Field80::Elt x = e.elt(F);
    EXPECT_LT(x.n, F.m_);
    x = e.subfield_elt(F);
    EXPECT_LT(x.n, F.m_);
  }
}

TEST(Random, GF2_128) {
  typedef GF2_128<> FieldGF;
  FieldGF F;
  SecureRandomEngine e;
  constexpr size_t N = 100;
  for (size_t i = 0; i < N; ++i) {
    FieldGF::Elt x = e.elt(F);
    // Every array of 128 bits is a valid element of GF2_128.
    // The main point here is verifying `elt` compiles.
    EXPECT_TRUE(x == x);
    x = e.subfield_elt(F);
    EXPECT_TRUE(x == x);
  }
}

TEST(Random, SecureRandomEngine) {
  SecureRandomEngine e;
  test_all(&e);
}

}  // namespace
}  // namespace proofs
