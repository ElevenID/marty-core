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

#include "algebra/fp.h"

#include <array>
#include <cstddef>
#include <cstdint>

#include "algebra/bogorng.h"
#include "algebra/fp24.h"
#include "algebra/fp_p128.h"
#include "algebra/fp_p256.h"
#include "algebra/fp_p256k1.h"
#include "algebra/fp_p384.h"
#include "algebra/fp_p521.h"
#include "algebra/nat.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
typename Field::Elt ckfrom_montgomery(typename Field::Elt a, const Field& F) {
  EXPECT_EQ(F.from_montgomery_reference(a), F.from_montgomery(a));
  EXPECT_EQ(a, F.to_montgomery(F.from_montgomery(a)));
  return a;
}

template <class Field>
typename Field::Elt ckadd(typename Field::Elt a, typename Field::Elt b,
                          const Field& F) {
  auto r = F.addf(a, b);
  EXPECT_EQ(r, F.addf(b, a));
  EXPECT_EQ(F.addf(r, F.two()), F.addf(F.addf(a, F.one()), F.addf(b, F.one())));
  EXPECT_EQ(a, F.subf(r, b));
  EXPECT_EQ(b, F.subf(r, a));
  return r;
}

template <class Field>
typename Field::Elt cksub(typename Field::Elt a, typename Field::Elt b,
                          const Field& F) {
  auto r = F.subf(a, b);
  EXPECT_EQ(r, F.subf(F.addf(a, F.one()), F.addf(b, F.one())));
  auto mr = F.subf(b, a);
  EXPECT_EQ(mr, F.subf(F.addf(b, F.one()), F.addf(a, F.one())));
  EXPECT_EQ(a, F.addf(b, r));
  EXPECT_EQ(b, F.addf(a, mr));
  EXPECT_EQ(F.zero(), F.addf(r, mr));
  return r;
}

template <class Field>
typename Field::Elt ckmul(typename Field::Elt a, typename Field::Elt b,
                          const Field& F) {
  auto r = F.mulf(a, b);
  EXPECT_EQ(r, F.mulf(b, a));

  auto ma = F.negf(a);
  auto mb = F.negf(b);
  EXPECT_EQ(r, F.mulf(ma, mb));
  EXPECT_EQ(r, F.mulf(mb, ma));
  return r;
}

template <class Field>
void fibonacci(const Field& F) {
  auto a = F.one();
  auto b = F.one();

  for (size_t i = 0; i < 1000; i++) {
    a = ckadd(a, b, F);
    b = ckadd(b, a, F);
  }

  auto want = F.of_string(
      "683570225957580664704539654917058010705540802936552456540755336779808245"
      "440805401495453431895311380272660372676952344747823819219271452667793994"
      "333830610140510541481970566409090181363729645376709552810486826470491443"
      "352935557914873104468563413548773589795462984251694710149425357586969989"
      "340097653954574021481981915195208508953842295456514672038375212197211572"
      "5761141759114990448978941370030912401573418221496592822626");

  EXPECT_EQ(a, want);
}

template <class Field>
void factorial(const Field& F) {
  auto p = F.one();
  auto fi = F.one();
  for (uint64_t i = 1; i <= 337; ++i) {
    p = ckmul(p, fi, F);
    fi = ckadd(fi, F.one(), F);
  }

  auto want = F.of_string(
      "130932804149088992546057261943598916651380085320056882046632369209980447"
      "366486195583875107499552077757320239493552004852577547570260331861859535"
      "521014367028762150336371971084184802220775697724840028097301334011793388"
      "942370614718341215113319703287766478296719019864501440605926667194653195"
      "515282444560161328301222855804492620971650056743347973226019758046208866"
      "500052558105710981673345457144935004205153930768986245233790635907756296"
      "677802809190469443074096751804464370890609618413796499897335752206338990"
      "966921419488285779097481797799327000523783874784902588031943372895509486"
      "862780297994201058534583425203348291866696425144320000000000000000000000"
      "000000000000000000000000000000000000000000000000000000000000");

  EXPECT_EQ(p, want);
}

template <class Field>
void mult(const Field& F) {
  for (uint64_t i = 0; i < 10; ++i) {
    for (uint64_t j = 0; j < 10; ++j) {
      EXPECT_EQ(ckmul(F.of_scalar(i), F.of_scalar(j), F), F.of_scalar(i * j));
    }
  }
}

template <class Field>
void inverse(const Field& F) {
  for (uint64_t i = 0; i < 1000; ++i) {
    auto x = F.of_scalar(i);
    F.invert(x);
    if (i == 0) {
      EXPECT_EQ(ckmul(F.of_scalar(i), x, F), F.zero());
    } else {
      EXPECT_EQ(ckmul(F.of_scalar(i), x, F), F.one());
    }
  }
}

template <class Field>
void neg(const Field& F) {
  for (uint64_t i = 0; i < 1000; ++i) {
    auto x = F.of_scalar(i);
    F.neg(x);
    EXPECT_EQ(ckadd(F.of_scalar(i), x, F), F.zero());
    EXPECT_EQ(ckadd(F.of_scalar(i), F.negf(F.of_scalar(i)), F), F.zero());
  }
}

template <class Field>
void of_scalar(const Field& F) {
  std::array<uint64_t, Field::kU64> n;
  for (size_t i = 0; i < Field::kU64; ++i) {
    n[i] = i + 47;
  }
  auto want = F.zero();
  auto base = F.of_scalar(1ull << 16);
  F.mul(base, base);  // base = 2^32
  F.mul(base, base);  // base = 2^64
  for (size_t i = Field::kU64; i-- > 0;) {
    want = F.addf(F.of_scalar(i + 47), F.mulf(base, want));
  }
  EXPECT_EQ(F.of_scalar_field(n), want);

  // check the identity
  //   of_scalar(sum_i b[i] 2^i) = sum_i b[i] beta(i)

  // small integers k = sum_i b[i] 2^i
  for (uint64_t k = 0; k < 1000; ++k) {
    auto sum = F.zero();
    for (size_t i = 0; i < 64; ++i) {
      uint64_t bit = (k >> i) & 1;
      if (bit) {
        F.add(sum, F.beta(i));
      }
    }
    EXPECT_EQ(F.of_scalar(k), sum);
  }

  // powers of two
  for (size_t i = 0; i < 64; ++i) {
    uint64_t k = static_cast<uint64_t>(1) << i;
    if (F.fits(k)) {
      EXPECT_EQ(F.of_scalar(k), F.beta(i));
    }
  }
}

template <size_t WX, class Field>
void reduce(const Field& F) {
  auto e = F.one();
  const Nat<WX> one(1);
  Nat<WX> n(1);

  // test all 2^i and 2^i - 1
  for (size_t i = 0; i < Nat<WX>::kBits; ++i) {
    auto x = F.reduce(n);
    EXPECT_EQ(x, e);

    auto em1 = F.subf(e, F.of_scalar(1));
    auto nm1 = n;
    nm1.sub(one);
    auto xm1 = F.reduce(nm1);
    EXPECT_EQ(xm1, em1);

    F.add(e, e);
    n.add(n);
  }
}

template <class Field>
void dot(const Field& F) {
  constexpr size_t n = 20;
  std::vector<Nat<1>> e(n);
  std::vector<typename Field::NatScaledForDot> d(n);

  uint64_t want = 0;
  for (size_t i = 0; i < n; ++i) {
    uint64_t ei = i * i + 3;
    uint64_t di = i + 7;
    e[i] = Nat<1>(ei);
    d[i] = F.prescale_for_dot(F.of_scalar(di));
    want += ei * di;
  }
  auto got = F.dot(n, e.data(), d.data());
  EXPECT_EQ(got, F.of_scalar(want));
}

// test add/sub around the -1..0 boundary in raw (not montgomery)
// space where wraparound occurs
template <class Field>
void wraparound(const Field& F) {
  int k = 32;
  auto f2k = F.of_scalar(2 * k);
  for (int i = -k; i <= k; ++i) {
    for (int j = -k; j <= k; ++j) {
      // cannot convert i, j via of_scalar, so hack around it.
      auto fi = F.subf(f2k, F.of_scalar(i + 2 * k));
      auto fj = F.subf(f2k, F.of_scalar(j + 2 * k));
      fi = ckfrom_montgomery(fi, F);
      fj = ckfrom_montgomery(fj, F);

      auto fa = F.subf(f2k, F.of_scalar(i + j + 2 * k));
      auto fs = F.subf(f2k, F.of_scalar(i - j + 2 * k));
      fa = ckfrom_montgomery(fa, F);
      fs = ckfrom_montgomery(fs, F);

      auto a = ckadd(fi, fj, F);
      auto s = cksub(fi, fj, F);
      EXPECT_EQ(a, fa);
      EXPECT_EQ(s, fs);
    }
  }
}

template <class Field>
void poly_evaluation_points(const Field& F) {
  constexpr size_t N = Field::kNPolyEvaluationPoints;
  for (size_t i = 0; i < N; i++) {
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

template <class Field>
void onefield(const Field& F) {
  mult(F);
  factorial(F);
  fibonacci(F);
  wraparound(F);
  neg(F);
  inverse(F);
  of_scalar(F);
  poly_evaluation_points(F);
  if (F.kSupportsDot) {
    dot(F);
    reduce<1>(F);
    reduce<2>(F);
    reduce<3>(F);
    reduce<4>(F);
    reduce<5>(F);
    reduce<6>(F);
    reduce<30>(F);
  }

  EXPECT_EQ(F.zero(), F.addf(F.one(), F.mone()));
  EXPECT_EQ(F.one(), F.addf(F.half(), F.half()));
  EXPECT_EQ(F.two(), F.addf(F.one(), F.one()));

  const uint64_t c = 0x123456789abcdef0ull;
  if (F.fits(c)) {
    EXPECT_EQ(F.of_string("0x123456789abcdef0"), F.of_scalar(c));
    EXPECT_EQ(F.of_string("0X123456789ABCDEF0"), F.of_scalar(c));
  }
}

TEST(Fp, AllSizes) {
  onefield(Fp24(8380417));   // ML-DSA44 prime
  onefield(Fp24(16777213));  // largest 24-bit prime
  onefield(Fp<1>("18446744073709551557"));
  onefield(Fp<2>("340282366920938463463374607431768211297"));
  onefield(Fp<3>("6277101735386680763835789423207666416102355444464034512659"));
  onefield(
      Fp<4>("115792089237316195423570985008687907853269984665640564039457584007"
            "913129639747"));
  onefield(
      Fp<5>("213598703592091008239502170616955211460270452235665276994704160782"
            "2219725780640550022962086936379"));
  onefield(
      Fp<6>("394020061963944792122790401001436138050797392704654466679482934042"
            "45721771497210611414266254884915640806627990306499"));
  onefield(Fp256<>());
  onefield(Fp256k1<>());
  onefield(Fp128<>());
  onefield(Fp384<>());
  onefield(Fp521<>());

  // Our field implementation "works" in a ring.
  // 3906555671 * 4254597877 = 16620823464218910467
  onefield(Fp<1>("16620823464218910467"));
  // 1057848127303065953 * 2108036397730900859 =
  // 2229982355626334583552843599381353627
  onefield(Fp<2>("2229982355626334583552843599381353627"));
}

TEST(Fp, ExactBits) {
  Fp<1> F17("17");
  EXPECT_EQ(F17.exact_bits_, 5);  // 17 is 10001 in binary, which is 5 bits

  Fp<1> F_large("18446744073709551557");  // Near 2^64
  EXPECT_EQ(F_large.exact_bits_, 64);

  Fp256k1<> F_secp256k1;
  // secp256k1 modulus is 256 bits exactly
  EXPECT_EQ(F_secp256k1.exact_bits_, 256);

  Fp384<> F_p384;
  EXPECT_EQ(F_p384.exact_bits_, 384);

  Fp521<> F_p521;
  EXPECT_EQ(F_p521.exact_bits_, 521);
}

TEST(Fp, SmallField) {
  Fp<1> F17("17");
  F17.of_scalar(0);
  F17.of_scalar(1);
  F17.of_scalar(2);

  uint8_t bad[8] = {17, 0, 0, 0, 0, 0, 0, 0};
  EXPECT_FALSE(F17.of_bytes_field(bad).has_value());
  EXPECT_FALSE(F17.of_bytes_subfield(bad).has_value());
}

TEST(Fp, RootOfUnity) {
  Fp<4> F(
      "218882428718392752222464057452572750885483644004160343436982041865758084"
      "95617");
  auto omega = F.of_string(
      "191032190679217139442913928276920700361456519573292863153056420048214621"
      "61904");
  for (size_t i = 0; i < 28; ++i) {
    EXPECT_NE(omega, F.one());
    omega = ckmul(omega, omega, F);
  }
  EXPECT_EQ(omega, F.one());
}

TEST(Fp, InverseSecp256k1) {
  Fp<4> F(
      "11579208923731619542357098500868790785326998466564056403945758400790"
      "8834671663");

  // invert a bunch of powers of two
  auto t = F.one();
  for (int i = 0; i < 1000; ++i) {
    auto ti = F.invertf(t);
    auto one = F.mulf(t, ti);
    EXPECT_EQ(one, F.one());
    // inverse(inverse(x)) =? x
    auto tii = F.invertf(ti);
    EXPECT_EQ(t, tii);

    F.add(t, t);
  }
}

TEST(Fp, castable) {
  Fp<4> F(
      "11579208923731619542357098500868790785326998466564056403945758400790"
      "8834671663");
  uint8_t b[32] = {0xDD, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  EXPECT_FALSE(F.of_bytes_field(b));
  b[31] = 0xEF;
  EXPECT_TRUE(F.of_bytes_field(b));
}

// ======= Benchmarks ============

template <class Field>
void bench_add(const Field& F, benchmark::State& state) {
  Bogorng<Field> rng(&F);
  auto a = rng.next();
  for (auto _ : state) {
    a = F.addf(a, a);
    benchmark::DoNotOptimize(a);
  }
}

template <class Field>
void bench_mul(const Field& F, benchmark::State& state) {
  Bogorng<Field> rng(&F);
  auto a = rng.next();
  for (auto _ : state) {
    a = F.mulf(a, a);
    benchmark::DoNotOptimize(a);
  }
}

void BM_Fp24_add(benchmark::State& state) {
  const Fp24 F(16777213);
  bench_add(F, state);
}
BENCHMARK(BM_Fp24_add);

void BM_Fp1_add(benchmark::State& state) {
  const Fp<1> F("18446744073709551557");
  bench_add(F, state);
}
BENCHMARK(BM_Fp1_add);

void BM_p256_add(benchmark::State& state) {
  const Fp256<true> F;
  bench_add(F, state);
}
BENCHMARK(BM_p256_add);

void BM_p256k1_add(benchmark::State& state) {
  const Fp256k1<true> F;
  bench_add(F, state);
}
BENCHMARK(BM_p256k1_add);

void BM_p384_add(benchmark::State& state) {
  const Fp384<true> F;
  bench_add(F, state);
}
BENCHMARK(BM_p384_add);

void BM_p521_add(benchmark::State& state) {
  const Fp521<true> F;
  bench_add(F, state);
}
BENCHMARK(BM_p521_add);

void BM_Fp24_mul(benchmark::State& state) {
  const Fp24 F(16777213);
  bench_mul(F, state);
}
BENCHMARK(BM_Fp24_mul);

void BM_Fp1_mul(benchmark::State& state) {
  const Fp<1> F("18446744073709551557");
  bench_mul(F, state);
}
BENCHMARK(BM_Fp1_mul);

void BM_p256_mul(benchmark::State& state) {
  const Fp256<true> F;
  bench_mul(F, state);
}
BENCHMARK(BM_p256_mul);

void BM_p256k1_mul(benchmark::State& state) {
  const Fp256k1<true> F;
  bench_mul(F, state);
}
BENCHMARK(BM_p256k1_mul);

void BM_p384_mul(benchmark::State& state) {
  const Fp384<true> F;
  bench_mul(F, state);
}
BENCHMARK(BM_p384_mul);

// Bench
void BM_p384_mul_normal(benchmark::State& state) {
  const Fp<6, true> F(
      "394020061963944792122790401001436138050797392704654466679482934042457217"
      "71496870329047266088258938001861606973112319");
  bench_mul(F, state);
}
BENCHMARK(BM_p384_mul_normal);

void BM_p521_mul(benchmark::State& state) {
  const Fp521<true> F;
  bench_mul(F, state);
}
BENCHMARK(BM_p521_mul);

}  // namespace
}  // namespace proofs
