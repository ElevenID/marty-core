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

#include "gf2k/gf2_128.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "algebra/blas.h"
#include "algebra/bogorng.h"
#include "algebra/compare.h"
#include "algebra/poly.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = GF2_128<4>;
using Elt = Field::Elt;
using CElt = Field::CElt;
const Field F;

/* Reference GF(2^128) implementation */
struct ref_gf2_128 {
  uint64_t l;
  uint64_t h;
  bool operator==(const ref_gf2_128& y) const { return l == y.l && h == y.h; }
};

ref_gf2_128 ref_gf2_128_xor(ref_gf2_128 a, ref_gf2_128 b) {
  return ref_gf2_128{a.l ^ b.l, a.h ^ b.h};
}
ref_gf2_128 ref_gf2_128_shl(ref_gf2_128 a, size_t n) {
  if (n == 0) {
    return a;
  } else if (n >= 128) {
    return ref_gf2_128{};
  } else if (n >= 64) {
    return ref_gf2_128{0, (a.l << (n - 64))};
  } else {
    return ref_gf2_128{(a.l << n), (a.h << n) | (a.l >> (64 - n))};
  }
}

static ref_gf2_128 refmul(ref_gf2_128 x, ref_gf2_128 y) {
  static const ref_gf2_128 poly{0x87, 0};
  ref_gf2_128 a{};
  for (size_t i = 0; i < 128; ++i) {
    uint64_t msb = a.h & 0x8000000000000000ull;
    a = ref_gf2_128_shl(a, 1);
    if (msb) {
      a = ref_gf2_128_xor(a, poly);
    }
    if (y.h & 0x8000000000000000ull) {
      a = ref_gf2_128_xor(a, x);
    }
    y = ref_gf2_128_shl(y, 1);
  }
  return a;
}

static Elt of_ref(const ref_gf2_128& ref) {
  std::array<uint64_t, 2> u{ref.l, ref.h};
  return F.of_scalar_field(u);
}

TEST(GF2_128, Constants) {
  ref_gf2_128 zero = {0, 0};
  ref_gf2_128 one = {1, 0};
  ref_gf2_128 x = {2, 0};
  EXPECT_EQ(F.zero(), of_ref(zero));
  EXPECT_EQ(F.one(), of_ref(one));
  EXPECT_EQ(F.x(), of_ref(x));

  EXPECT_EQ(F.zero(), F.invertf(F.zero()));

  EXPECT_EQ(F.one(), F.mulf(F.x(), F.invx()));
  EXPECT_EQ(F.invx(), F.invertf(F.x()));
  EXPECT_EQ(F.x(), F.invertf(F.invx()));
}

TEST(GF2_128, Invert0) {
  for (uint64_t i = 1; i < 1000; ++i) {
    Elt fi = F.of_scalar(i);
    EXPECT_EQ(F.one(), F.mulf(fi, F.invertf(fi)));
  }
  for (uint64_t i = 1; i < 1000; ++i) {
    Elt fi = F.of_scalar_field(i);
    EXPECT_EQ(F.one(), F.mulf(fi, F.invertf(fi)));
  }
}

TEST(GF2_128, Invert1) {
  Elt a = F.x(), b = F.invx();
  for (uint64_t i = 0; i < 1000; ++i) {
    EXPECT_EQ(F.one(), F.mulf(a, b));
    F.mul(a, F.x());
    F.mul(b, F.invx());
  }
}

TEST(GF2_128, Cmp) {
  ref_gf2_128 one = {1, 0};
  for (size_t i = 0; i < 128; ++i) {
    for (size_t j = 0; j < 128; ++j) {
      ref_gf2_128 x = ref_gf2_128_shl(one, i);
      ref_gf2_128 y = ref_gf2_128_shl(one, j);
      EXPECT_EQ(x == y, of_ref(x) == of_ref(y));
      EXPECT_EQ(i == j, of_ref(x) == of_ref(y));
    }
  }
}

TEST(GF2_128, Mul) {
  ref_gf2_128 one = {1, 0};
  for (size_t i = 0; i < 129; ++i) {
    for (size_t j = 0; j < 129; ++j) {
      ref_gf2_128 x = ref_gf2_128_shl(one, i);
      ref_gf2_128 y = ref_gf2_128_shl(one, j);
      ref_gf2_128 a = refmul(x, y);
      Elt b = F.mulf(of_ref(x), of_ref(y));
      EXPECT_EQ(of_ref(a), b);
    }
  }
}

TEST(GF2_128, PolyEvaluationPoint) {
  constexpr size_t N = Field::kNPolyEvaluationPoints;
  for (size_t i = 0; i < N; i++) {
    EXPECT_TRUE(F.in_subfield(F.poly_evaluation_point(i)));
    for (size_t j = 0; j < N; j++) {
      if (i != j) {
        EXPECT_NE(F.poly_evaluation_point(i), F.poly_evaluation_point(j));
      }
    }
  }
  for (size_t i = 1; i < N; i++) {
    for (size_t k = N; k-- > i;) {
      auto dx =
          F.subf(F.poly_evaluation_point(k), F.poly_evaluation_point(k - i));
      EXPECT_EQ(F.one(), F.mulf(dx, F.newton_denominator(k, i)));
    }
  }
}

template <size_t N>
void one_test_eval_lagrange() {
  using T = Poly<N, Field>;
  Bogorng<Field> rng(&F);
  const typename T::dot_interpolation dot_interp(F);

  T C, L;
  for (size_t iter = 0; iter < 10; ++iter) {
    for (size_t i = 0; i < N; ++i) {
      C[i] = rng.next();
    }

    for (size_t i = 0; i < N; ++i) {
      // Lagrange basis
      L[i] = C.eval_monomial(F.poly_evaluation_point(i), F);
    }

    for (size_t iter1 = 0; iter1 < 10; iter1++) {
      Elt r = rng.next();
      Elt got_val = L.eval_lagrange(r, F);
      Elt want_val = C.eval_monomial(r, F);
      EXPECT_EQ(got_val, want_val);

      T coef = dot_interp.coef(r, F);
      Elt got_dot = Blas<Field>::dot(N, &coef[0], 1, &L[0], 1, F);
      EXPECT_EQ(got_dot, want_val);
    }
  }
}

TEST(GF2_128, EvalLagrange) {
  one_test_eval_lagrange<1>();
  one_test_eval_lagrange<2>();
  one_test_eval_lagrange<3>();
  one_test_eval_lagrange<4>();
  one_test_eval_lagrange<5>();
  one_test_eval_lagrange<6>();
}

// Ensure no short loops in Bogorng.
// Bogorng is optimized for prime fields.  This test ensures
// the parameters do not break simple testing for GF2_128.
TEST(GF2_128, Bogorng) {
  Bogorng<Field> rng(&F);
  Elt start = rng.next();
  for (size_t i = 0; i < 1000000; ++i) {
    Elt x = rng.next();
    EXPECT_NE(x, start);
  }
}

template <size_t N>
void one_test_extend() {
  using T2 = Poly<2, Field>;
  using FT = Poly<N, Field>;
  Bogorng<Field> rng(&F);

  // Test the linear extension.  Start with a polynomial
  // L2 of degree <2, and extend it to a polynomial L
  // of degree <N, then evaluate both at random points.
  for (size_t iter = 0; iter < 10; ++iter) {
    T2 L2;
    L2[0] = rng.next();
    L2[1] = rng.next();

    FT L = FT::extend(L2, F);

    for (size_t iter1 = 0; iter1 < 10; iter1++) {
      Elt r = rng.next();
      Elt got = L.eval_lagrange(r, F);
      Elt got2 = L2.eval_lagrange(r, F);
      EXPECT_EQ(got, got2);
    }
  }
}

TEST(GF2_128, Extend) {
  one_test_extend<2>();
  one_test_extend<3>();
  one_test_extend<4>();
  one_test_extend<5>();
  one_test_extend<6>();
}

void expect_order(size_t log_order, const Elt x0) {
  // EXPECT_NE(x, x0) is necessary but not sufficient.  We should
  // really check all factors of (2^log_order-1).  At the very least
  // this test prevents confusing x() with the generator of the
  // subfield.
  Elt x = F.mulf(x0, x0);
  for (size_t i = 1; i < log_order; ++i) {
    EXPECT_NE(x, x0);
    F.mul(x, x);
  }
  EXPECT_EQ(x, x0);
}

TEST(GF2_128, X) {
  expect_order(Field::kBits, F.x());
  expect_order(Field::kBits, F.invx());
}

TEST(GF2_128, Beta) {
  EXPECT_EQ(F.beta(0), F.one());

  Elt r(F.beta(1));

  // Expected: x^126 + x^124 + x^123 + x^122 + x^118 + x^116 + x^115 +
  // x^112 + x^110 + x^109 + x^108 + x^104 + x^103 + x^98 + x^97 +
  // x^96 + x^94 + x^93 + x^92 + x^90 + x^88 + x^80 + x^79 + x^78 +
  // x^76 + x^74 + x^71 + x^69 + x^68 + x^67 + x^63 + x^62 + x^61 +
  // x^60 + x^56 + x^55 + x^50 + x^49 + x^48 + x^44 + x^43 + x^42 +
  // x^41 + x^32 + x^31 + x^29 + x^28 + x^26 + x^25 + x^22 + x^19 +
  // x^18 + x^17 + x^16 + x^15 + x^14 + x^12 + x^11 + x^9 + x^6 + x^3
  // + x^2
  std::array<uint64_t, 2> want = {0xF1871E01B64FDA4Cull, 0x5C5971877501D4B8ull};
  EXPECT_EQ(r, F.of_scalar_field(want));
  expect_order(Field::kSubFieldBits, F.beta(1));

  for (size_t i = 0; i < Field::kSubFieldBits; ++i) {
    EXPECT_TRUE(F.in_subfield(F.beta(i)));
  }
}

TEST(GF2_128, OfScalar) {
  // test that of_scalar() returns the expected linear
  // combination of the basis
  size_t n = 1 << F.kSubFieldBits;
  for (size_t i = 0; i < n; ++i) {
    Elt e = F.of_scalar(i);
    EXPECT_TRUE(F.in_subfield(e));

    Elt t = F.zero();
    for (size_t k = 0, u = i; u != 0; ++k, u >>= 1) {
      if (u & 1) {
        F.add(t, F.beta(k));
      }
    }
    EXPECT_EQ(t, e);
  }
}

TEST(GF2_128, SubFieldSize) {
  // test that all subfield elements are distinct
  size_t n = 1u << F.kSubFieldBits;
  std::vector<Elt> scalars(n);

  for (uint64_t i = 0; i < n; ++i) {
    scalars[i] = F.of_scalar(i);
  }
  std::sort(scalars.begin(), scalars.end(),
            [&](const Elt& x, const Elt& y) { return elt_less_than(x, y, F); });
  for (uint64_t i = 0; i + 1 < n; ++i) {
    EXPECT_NE(scalars[i], scalars[i + 1]);
  }
}

TEST(GF2_128, Counter) {
  size_t n = (1u << F.kSubFieldBits) - 1u;

  // test that all counters are distinct
  std::vector<CElt> counters(n);

  for (uint64_t i = 0; i < n; ++i) {
    CElt ctr = F.as_counter(i);
    Elt e = F.znz_indicator(ctr);
    counters[i] = ctr;

    if (i == 0) {
      EXPECT_EQ(e, F.zero());
      EXPECT_EQ(ctr.e, F.one());
    } else {
      EXPECT_NE(e, F.zero());
      EXPECT_NE(ctr.e, F.one());
    }
    if (i == 1) {
      EXPECT_EQ(ctr.e, F.g());
    } else {
      EXPECT_NE(ctr.e, F.g());
    }
    if (i == n - 1) {
      EXPECT_EQ(ctr.e, F.invg());
    } else {
      EXPECT_NE(ctr.e, F.invg());
    }
  }
  std::sort(
      counters.begin(), counters.end(),
      [&](const CElt& x, const CElt& y) { return elt_less_than(x.e, y.e, F); });

  for (uint64_t i = 0; i + 1 < n; ++i) {
    EXPECT_NE(counters[i], counters[i + 1]);
  }
}

TEST(GF2_128, Bytes) {
  size_t n = 1 << F.kSubFieldBits;
  for (size_t i = 0; i < n; ++i) {
    Elt e = F.of_scalar(i);
    EXPECT_TRUE(F.in_subfield(e));

    uint8_t sbuf[F.kSubFieldBytes];
    F.to_bytes_subfield(sbuf, e);
    auto es = F.of_bytes_subfield(sbuf);
    EXPECT_TRUE(es != std::nullopt);
    EXPECT_EQ(e, es.value());

    uint8_t fbuf[F.kBytes];
    F.to_bytes_field(fbuf, e);
    auto ef = F.of_bytes_field(fbuf);
    EXPECT_TRUE(ef != std::nullopt);
    EXPECT_EQ(e, ef.value());
  }
}
}  // namespace

namespace subfield {
template <size_t subfield_log_bits>
void test_subfield() {
  using Field = GF2_128<subfield_log_bits>;
  using Elt = typename Field::Elt;
  const Field F;
  constexpr uint64_t k1 = 1;  // for uint64_t type

  // test injection into the subfield, but since the subfield may be
  // too large for exhaustive check, only test on all combinations of
  // three bits.
  size_t l = F.kSubFieldBits;

  for (size_t b0 = 0; b0 < l; ++b0) {
    for (size_t b1 = 0; b1 < l; ++b1) {
      for (size_t b2 = 0; b2 < l; ++b2) {
        uint64_t i = (k1 << b0) ^ (k1 << b1) ^ (k1 << b2);
        Elt e = F.of_scalar(i);
        EXPECT_TRUE(F.in_subfield(e));

        uint8_t sbuf[F.kSubFieldBytes];
        F.to_bytes_subfield(sbuf, e);
        auto es = F.of_bytes_subfield(sbuf);
        EXPECT_TRUE(es != std::nullopt);
        EXPECT_EQ(e, es.value());
      }
    }
  }
}

TEST(GF2_128, Subfields) {
  test_subfield<3>();
  test_subfield<4>();
  test_subfield<5>();
  test_subfield<6>();
  // not enough bits in uint64_t for a (1<<7)-bit subfield
}

}  // namespace subfield
}  // namespace proofs
