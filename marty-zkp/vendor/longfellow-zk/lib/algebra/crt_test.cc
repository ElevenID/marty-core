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

#include "algebra/crt.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/bogorng.h"
#include "algebra/convolution.h"
#include "algebra/crt_convolution.h"
#include "algebra/fft.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/fp_p256.h"
#include "algebra/fp_p384.h"
#include "algebra/fp_p521.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {

namespace {

using Fp1 = Fp<1>;
Fp1 fp1("4179340454199820289");

template <class Field, class CRT>
void testFp(const CRT& crt, const Field& F) {
  Bogorng<Field> rng(&F);
  for (size_t i = 0; i < 1000; ++i) {
    auto x = rng.next();
    auto y = rng.next();
    auto x_crt = crt.to_crt(x);
    auto y_crt = crt.to_crt(y);
    auto gxg = crt.to_field(x_crt);
    EXPECT_EQ(x, gxg);

    auto z = F.addf(x, y);
    auto z_crt = crt.addf(x_crt, y_crt);
    auto got = crt.to_field(z_crt);
    EXPECT_EQ(z, got);

    auto zs_crt = crt.subf(z_crt, y_crt);
    auto x2 = crt.to_field(zs_crt);
    EXPECT_EQ(x2, x);

    auto zm = F.mulf(x, y);
    auto zm_crt = crt.mulf(x_crt, y_crt);
    auto gotm = crt.to_field(zm_crt);
    EXPECT_EQ(zm, gotm);
  }
}

// Verifies that performing a forward FFT followed by a backward FFT over the
// Chinese Remainder Theorem (CRT) representation recovers the original input
// vector, up to the expected scale factor of `n`.
template <typename Field>
void TestFFTInverse(const Field& F) {
  using Elt = typename Field::Elt;
  Bogorng<Field> rng(&F);

  size_t n = 1024;
  std::vector<Elt> A(n);
  for (size_t i = 0; i < n; ++i) {
    A[i] = rng.next();
  }

  // Same over CRT.
  using CRT = CRT256<Field>;
  using CRTElt = typename CRT::Elt;
  CRT crt(F);
  auto omega_crt = crt.omega();
  uint64_t omega_order = crt.omega_order();

  std::vector<Elt> C(n);
  std::vector<CRTElt> a_crt(n, crt.zero());
  for (size_t i = 0; i < n; ++i) {
    a_crt[i] = crt.to_crt(A[i]);
  }
  FFT<CRT>::fftf(&a_crt[0], n, omega_crt, omega_order, crt);
  FFT<CRT>::fftb(&a_crt[0], n, omega_crt, omega_order, crt);
  for (size_t i = 0; i < n; ++i) {
    C[i] = crt.to_field(a_crt[i]);
    F.mul(C[i], F.invertf(F.of_scalar(n)));
    EXPECT_EQ(C[i], A[i]);
  }
}

TEST(CrtTest, Fp1Test) {
  const Fp1 fp("8380417");
  CRT<1, Fp1> crt(fp);
  testFp(crt, fp);
  TestFFTInverse(fp);
}

TEST(CrtTest, Fp256Test) {
  Fp256<> F;
  CRT256<Fp256<>> crt(F);
  testFp(crt, F);
  TestFFTInverse(F);
}

TEST(CrtTest, Fp384Test) {
  Fp384<> F;
  CRT384<Fp384<>> crt(F);
  testFp(crt, F);
  TestFFTInverse(F);
}

TEST(CrtTest, Fp521Test) {
  Fp521<> F;
  CRT521<Fp521<>> crt(F);
  testFp(crt, F);
  TestFFTInverse(F);
}

TEST(CrtTest, RootOfUnity) {
  CRT521<Fp1> crt(fp1);
  auto omega = crt.omega();

  for (size_t i = 1; i < crt.omega_order(); i *= 2) {
    // Ensure all intermediate powers of omega are not unity.
    EXPECT_NE(omega, crt.one());
    crt.mul(omega, omega);
  }
  EXPECT_EQ(omega, crt.one());
}

TEST(CrtTest, FFTInverse) {
  using Fp = Fp<4>;
  const Fp F(
      "218882428718392752222464057452572750885483644004160343436982041865758084"
      "95617");
  TestFFTInverse(F);
}

// Verifies that a convolution performed using FFT over the base field `Fp`
// agrees with a convolution performed using the CRT approach. This test
// requires the target field `Fp` to have a known primitive root of unity
// (`omegaf`) of order `omegaf_order` large enough to support the FFT over
// vectors of size M + N - 1.
TEST(CrtTest, ConvolutionTest) {
  using Fp = Fp<4>;

  const Fp F(
      "218882428718392752222464057452572750885483644004160343436982041865758084"
      "95617");

  const auto omegaf = F.of_string(
      "191032190679217139442913928276920700361456519573292863153056420048214621"
      "61904");
  const uint64_t omegaf_order = 1ull << 28;

  static constexpr size_t N = 37;  // Degree 36 polynomial
  static constexpr size_t M = 256;
  Bogorng<Fp> rng(&F);

  // Generate random input in Fp.
  std::vector<Fp::Elt> x(N);
  std::vector<Fp::Elt> y(M);
  std::vector<Fp::Elt> want(M);
  for (size_t i = 0; i < N; ++i) {
    x[i] = rng.next();
  }
  for (size_t i = 0; i < M; ++i) {
    y[i] = rng.next();
  }

  FFTConvolution<Fp> conv(N, M, F, omegaf, omegaf_order, y.data());
  conv.convolution(x.data(), want.data());

  std::vector<Fp::Elt> got(M);
  CRTConvolution<CRT256<Fp>, Fp> crt_conv(N, M, F, y.data());
  crt_conv.convolution(x.data(), got.data());

  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(got[i], want[i]);
  }
}

// ================= Benchmarks ===================

void BM_mul_fp1(benchmark::State& state) {
  Fp<1> f("4179340454199820289");
  auto x = f.two();
  for (auto _ : state) {
    f.mul(x, x);
  }
}
BENCHMARK(BM_mul_fp1);


void BM_crt_add256(benchmark::State& state) {
  CRT256<Fp1> crt(fp1);
  auto a = crt.to_crt(fp1.of_scalar(112121));
  for (auto _ : state) {
    auto b = crt.addf(a, a);
    benchmark::DoNotOptimize(b);
  }
}

BENCHMARK(BM_crt_add256);

void BM_crt_mul256(benchmark::State& state) {
  CRT256<Fp1> crt(fp1);
  auto a = crt.to_crt(fp1.of_scalar(112121));
  for (auto _ : state) {
    auto b = crt.mulf(a, a);
    benchmark::DoNotOptimize(b);
  }
}
BENCHMARK(BM_crt_mul256);

void BM_crt_mul384(benchmark::State& state) {
  CRT384<Fp1> crt(fp1);
  auto a = crt.to_crt(fp1.of_scalar(112121));
  for (auto _ : state) {
    auto b = crt.mulf(a, a);
    benchmark::DoNotOptimize(b);
  }
}
BENCHMARK(BM_crt_mul384);

void BM_crt_mul521(benchmark::State& state) {
  CRT521<Fp1> crt(fp1);
  auto a = crt.to_crt(fp1.of_scalar(112121));
  for (auto _ : state) {
    auto b = crt.mulf(a, a);
    benchmark::DoNotOptimize(b);
  }
}
BENCHMARK(BM_crt_mul521);

template <class CRT, class Field>
void benchmark_tofield(benchmark::State& state, const CRT& crt,
                       const Field& F) {
  Bogorng<Field> rng(&F);
  auto x = rng.next();
  auto x_crt = crt.to_crt(x);
  for (auto _ : state) {
    auto want = crt.to_field(x_crt);
    benchmark::DoNotOptimize(want);
  }
}

void BM_ToField_p256(benchmark::State& state) {
  Fp256<> F;
  CRT256<Fp256<>> crt(F);
  benchmark_tofield(state, crt, F);
}
BENCHMARK(BM_ToField_p256);

void BM_ToField_p384(benchmark::State& state) {
  Fp384<> F;
  CRT384<Fp384<>> crt(F);
  benchmark_tofield(state, crt, F);
}
BENCHMARK(BM_ToField_p384);

void BM_ToField_p521(benchmark::State& state) {
  Fp521<> F;
  CRT521<Fp521<>> crt(F);
  benchmark_tofield(state, crt, F);
}
BENCHMARK(BM_ToField_p521);


void BM_conv(benchmark::State& state) {
  using Fp256 = Fp256<>;
  using Fp256_2 = Fp2<Fp256>;
  using FFT_p256_2 = FFTExtConvolutionFactory<Fp256, Fp256_2>;
  const Fp256 fp256;
  const Fp256_2 fp256_2(fp256);
  const FFT_p256_2 fft_p256_2(
      fp256, fp256_2,
      fp256_2.of_string(
          "11264922414641028187350045760969025837301884043048940872"
          "9223714171582664680802",
          "84087994358540907695740461427818660560182168997182378749313018254450"
          "460212908"),
      1ull << 31);

  static constexpr size_t N = 800;  // Degree 36 polynomial
  static constexpr size_t M = 32768;
  Bogorng<Fp256> rng(&fp256);

  // Generate random input in Fp.
  std::vector<Fp256::Elt> x(N);
  std::vector<Fp256::Elt> y(M);
  std::vector<Fp256::Elt> want(M);
  for (size_t i = 0; i < N; ++i) {
    x[i] = rng.next();
  }
  for (size_t i = 0; i < M; ++i) {
    y[i] = rng.next();
  }

  FFTExtConvolution<Fp256, Fp256_2> conv(
      N, M, fp256, fp256_2,
      fp256_2.of_string(
          "11264922414641028187350045760969025837301884043048940872"
          "9223714171582664680802",
          "84087994358540907695740461427818660560182168997182378749313018254450"
          "460212908"),
      1ull << 31, y.data());

  for (auto _ : state) {
    conv.convolution(x.data(), want.data());
    benchmark::DoNotOptimize(want);
  }
}
BENCHMARK(BM_conv);

template <class CRT, class Field>
void benchmarkCRTConv(benchmark::State& state, const Field& F) {
  static constexpr size_t N = 800;
  static constexpr size_t M = 32768;
  Bogorng<Field> rng(&F);

  // Generate random input in Fp.
  std::vector<typename Field::Elt> x(N);
  std::vector<typename Field::Elt> y(M);
  for (size_t i = 0; i < N; ++i) {
    x[i] = rng.next();
  }
  for (size_t i = 0; i < M; ++i) {
    y[i] = rng.next();
  }

  std::vector<typename Field::Elt> got(M);
  CRTConvolution<CRT, Field> crt_conv(N, M, F, y.data());
  for (auto _ : state) {
    crt_conv.convolution(x.data(), got.data());
    benchmark::DoNotOptimize(got);
  }
}

void BM_crtconv_p256(benchmark::State& state) {
  Fp256<> F;
  benchmarkCRTConv<CRT256<Fp256<>>, Fp256<>>(state, F);
}
BENCHMARK(BM_crtconv_p256);

void BM_crtconv_p384(benchmark::State& state) {
  Fp384<> F;
  benchmarkCRTConv<CRT384<Fp384<>>, Fp384<>>(state, F);
}
BENCHMARK(BM_crtconv_p384);

void BM_crtconv_p521(benchmark::State& state) {
  Fp521<> F;
  benchmarkCRTConv<CRT521<Fp521<>>, Fp521<>>(state, F);
}
BENCHMARK(BM_crtconv_p521);


}  // namespace
}  // namespace proofs
