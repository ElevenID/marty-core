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

#include "algebra/fp24_6.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include "algebra/fp24.h"
#include "algebra/nat.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
constexpr uint64_t kP = 8380417;
constexpr uint32_t kBeta = 7;
const Fp24 base(kP);
using Field = Fp24_6;
const Field ext(base, kBeta);
using Elt = Field::Elt;
using Scalar = Field::Scalar;

void test_addsub(const std::array<uint64_t, 6>& a,
                 const std::array<uint64_t, 6>& b) {
  std::array<uint64_t, 6> c;
  std::array<uint64_t, 6> d;
  for (size_t i = 0; i < 6; ++i) {
    c[i] = a[i] + b[i];
    d[i] = a[i] >= b[i] ? (a[i] - b[i]) : ((kP + a[i]) - b[i]);
  }
  Elt aa = ext.of_scalar_field(a);
  Elt bb = ext.of_scalar_field(b);
  Elt cc = ext.of_scalar_field(c);
  Elt dd = ext.of_scalar_field(d);
  EXPECT_EQ(cc, ext.addf(aa, bb));
  EXPECT_EQ(dd, ext.subf(aa, bb));
}

void test_mul(const std::array<uint64_t, 6>& a,
              const std::array<uint64_t, 6>& b) {
  std::array<uint64_t, 6> c = {};
  for (size_t i = 0; i < 6; ++i) {
    for (size_t j = 0; j < 6; ++j) {
      uint64_t z = a[i] * b[j];
      if (i + j < 6) {
        c[i + j] += z;
      } else {
        c[i + j - 6] += kBeta * z;
      }
    }
  }
  Elt aa = ext.of_scalar_field(a);
  Elt bb = ext.of_scalar_field(b);
  Elt cc = ext.of_scalar_field(c);
  EXPECT_EQ(cc, ext.mulf(aa, bb));
  EXPECT_EQ(ext.negf(cc), ext.mulf(ext.negf(aa), bb));
  EXPECT_EQ(ext.negf(cc), ext.mulf(ext.negf(bb), aa));
}

void test_invert(const std::array<uint64_t, 6>& a) {
  Elt aa = ext.of_scalar_field(a);
  if (aa != ext.zero()) {
    Elt aa1 = ext.invertf(aa);
    EXPECT_EQ(ext.mulf(aa, aa1), ext.one());
  }
}

TEST(Fp24_6, Mul) {
  // (1+2*x+7*x^2+8*x^3+13*x^4+22*x^5) *
  // (33+3*x+7*x^2+2*x^3+9*x^4+11*x^5) =
  //   864*x^5 + 2209*x^4 + 2688*x^3 + 1987*x^2 + 2372*x + 1839
  //    (mod x^6 - 7)
  const std::array<uint64_t, 6> a = {1, 2, 7, 8, 13, 22};
  const std::array<uint64_t, 6> b = {33, 3, 7, 2, 9, 11};
  const std::array<uint64_t, 6> c = {1839, 2372, 1987, 2688, 2209, 864};
  Elt aa = ext.of_scalar_field(a);
  Elt bb = ext.of_scalar_field(b);
  Elt cc = ext.of_scalar_field(c);
  EXPECT_EQ(cc, ext.mulf(aa, bb));
  EXPECT_EQ(cc, ext.mulf(bb, aa));
}

/*
 In pari/gp:
? p=8380417
? e=Mod(1,p)
? 1/Mod((1+2*x+7*x^2+8*x^3+13*x^4+22*x^5),x^6*e-7*e)

%94 = Mod(Mod(7307072, 8380417)*x^5 + Mod(2339325, 8380417)*x^4 + Mod(7220786,
8380417)*x^3 + Mod(3345369, 8380417)*x^2 + Mod(8279824, 8380417)*x +
Mod(3238248, 8380417), Mod(1, 8380417)*x^6 + Mod(8380410, 8380417))

*/
TEST(Fp24_6, Inverse) {
  const std::array<uint64_t, 6> a = {1, 2, 7, 8, 13, 22};
  const std::array<uint64_t, 6> inva = {3238248, 8279824, 3345369,
                                        7220786, 2339325, 7307072};
  Elt aa = ext.of_scalar_field(a);
  Elt invaa = ext.of_scalar_field(inva);
  EXPECT_EQ(invaa, ext.invertf(aa));
}

TEST(Fp24_6, Exhaustive) {
  std::array<uint64_t, 6> a;
  std::array<uint64_t, 6> b;
  uint64_t ub = 3;
  for (a[0] = 0; a[0] < ub; ++a[0]) {
    for (a[1] = 0; a[1] < ub; ++a[1]) {
      for (a[2] = 0; a[2] < ub; ++a[2]) {
        for (a[3] = 0; a[3] < ub; ++a[3]) {
          for (a[4] = 0; a[4] < ub; ++a[4]) {
            for (a[5] = 0; a[5] < ub; ++a[5]) {
              test_invert(a);
              for (b[0] = 0; b[0] < ub; ++b[0]) {
                for (b[1] = 0; b[1] < ub; ++b[1]) {
                  for (b[2] = 0; b[2] < ub; ++b[2]) {
                    for (b[3] = 0; b[3] < ub; ++b[3]) {
                      for (b[4] = 0; b[4] < ub; ++b[4]) {
                        for (b[5] = 0; b[5] < ub; ++b[5]) {
                          test_addsub(a, b);
                          test_mul(a, b);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

TEST(Fp24_6, OfScalar) {
  // check the identity
  //   of_scalar(sum_i b[i] 2^i) = sum_i b[i] beta(i)

  // small integers k = sum_i b[i] 2^i
  for (uint64_t k = 0; k < 1000; ++k) {
    auto sum = ext.zero();
    for (size_t i = 0; i < 64; ++i) {
      uint64_t bit = (k >> i) & 1;
      if (bit) {
        ext.add(sum, ext.beta(i));
      }
    }
    EXPECT_EQ(ext.of_scalar(k), sum);
  }

  // powers of two
  for (size_t i = 0; i < 64; ++i) {
    uint64_t k = static_cast<uint64_t>(1) << i;
    if (ext.fits(k)) {
      EXPECT_EQ(ext.of_scalar(k), ext.beta(i));
    }
  }
}

TEST(Fp24, OfStringHex) {
  Fp24 F(16777213);
  EXPECT_EQ(F.of_string("0X123"), F.of_scalar(0x123));
}

TEST(Fp24, Unimplemented) {
  Fp24 F(16777213);
  EXPECT_DEATH(F.prescale_for_dot(F.one()), "prescale_for_dot\\(\\)");
  EXPECT_DEATH(F.dot(0, nullptr, nullptr), "dot\\(\\)");
  Nat<2> n2(1);
  EXPECT_DEATH(F.reduce(n2), "reduce\\(\\)");
}

void BM_Fp24_6_add(benchmark::State& state) {
  const std::array<uint64_t, 6> a = {1, 2, 7, 8, 13, 22};
  const std::array<uint64_t, 6> b = {99, 98, 88, 86, 12, 17};
  Elt aa = ext.of_scalar_field(a);
  Elt bb = ext.of_scalar_field(b);
  for (auto _ : state) {
    ext.add(aa, bb);
    benchmark::DoNotOptimize(aa);
  }
}
BENCHMARK(BM_Fp24_6_add);

void BM_Fp24_6_mul(benchmark::State& state) {
  const std::array<uint64_t, 6> a = {1, 2, 7, 8, 13, 22};
  const std::array<uint64_t, 6> b = {99, 98, 88, 86, 12, 17};
  Elt aa = ext.of_scalar_field(a);
  Elt bb = ext.of_scalar_field(b);
  for (auto _ : state) {
    ext.mul(aa, bb);
    benchmark::DoNotOptimize(aa);
  }
}
BENCHMARK(BM_Fp24_6_mul);
}  // namespace
}  // namespace proofs
