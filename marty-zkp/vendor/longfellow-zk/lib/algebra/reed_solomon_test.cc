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

#include "algebra/reed_solomon.h"

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/blas.h"
#include "algebra/bogorng.h"
#include "algebra/convolution.h"
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/fp_p128.h"
#include "algebra/fp_p256.h"
#include "algebra/interpolation.h"
#include "algebra/poly.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
const Fp<4> F(
    "21888242871839275222246405745257275088548364400416034343698204186575808495"
    "617");
const Fp<1> G("18446744069414584321");

const auto omegaf = F.of_string(
    "19103219067921713944291392827692070036145651957329286315305642004821462161"
    "904");
const uint64_t omegaf_order = 1ull << 28;

const auto omegag = G.of_string("1753635133440165772");
const uint64_t omegag_order = 1ull << 32;

static constexpr size_t N = 37;  // Degree 36 polynomial
static constexpr size_t M = 256;

template <class Field>
class SlowConvolution {
  using Elt = typename Field::Elt;

 public:
  SlowConvolution(size_t n, size_t m, const Field& f, const Elt y[/*m*/])
      : n_(n), m_(m), f_(f), y_(m) {
    Blas<Field>::copy(m, &y_[0], 1, y, 1);
  }

  // Computes z[k] = \sum_{i=0}^{n-1} x[i] y[k-i].
  // input x has n entries.
  // y has size m, and only the first m entries of the convolution are computed.
  // So y can be zero padded with n zeroes to compute full convolution.
  void convolution(const Elt x[/*n_*/], Elt z[/*m_*/]) const {
    for (size_t k = 0; k < m_; ++k) {
      Elt s = f_.zero();
      for (size_t i = 0; (i < n_) && (k >= i); ++i) {
        if (k >= i && (k - i) < m_) {
          f_.add(s, f_.mulf(x[i], y_[k - i]));
        }
      }
      z[k] = s;
    }
  }

 private:
  size_t n_;
  size_t m_;
  const Field& f_;
  std::vector<Elt> y_;
};

template <class Field>
class SlowConvolutionFactory {
  using Elt = typename Field::Elt;

 public:
  using Convolver = SlowConvolution<Field>;

  explicit SlowConvolutionFactory(const Field& f) : f_(f) {}

  std::unique_ptr<const Convolver> make(size_t n, size_t m,
                                        const Elt y[/*m*/]) const {
    return std::make_unique<const Convolver>(n, m, f_, y);
  }

 private:
  const Field& f_;
};

template <class Field>
void one_field_reed_solomon(const typename Field::Elt& omega,
                            uint64_t omega_order, const Field& f) {
  using Elt = typename Field::Elt;

  using Interpolation = Interpolation<N, Field>;
  using FFTConvolutionFactory = FFTConvolutionFactory<Field>;
  using SlowConvolutionFactory = SlowConvolutionFactory<Field>;
  using CrtConvolutionFactory = CrtConvolutionFactory<CRT256<Field>, Field>;
  using Poly = Poly<N, Field>;  // N-tuple, i.e., at most N-1 degree polynomial

  Bogorng<Field> rng(&f);
  Poly P;
  // arbitrary coefficients
  for (size_t i = 0; i < N; ++i) {
    P[i] = f.of_scalar(i * i * i + (i & 0xF) + (i ^ (i << 2)));
  }

  // lagrange basis, i.e., values at first M points
  std::vector<Elt> L(M);
  for (size_t i = 0; i < M; ++i) {
    Elt x = f.of_scalar(i);
    L[i] = Interpolation::eval_monomial(P, x, f);
  }

  std::vector<Elt> L2(M);
  for (size_t i = 0; i < N; ++i) {
    L2[i] = L[i];
  }

  FFTConvolutionFactory factory(f, omega, omega_order);
  ReedSolomon<Field, FFTConvolutionFactory> r(N, M, f, factory);
  r.interpolate(&L2[0]);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L2[i], L[i]);
  }

  std::vector<Elt> L3(M);
  for (size_t i = 0; i < N; ++i) {
    L3[i] = L[i];
  }
  SlowConvolutionFactory slow_factory(f);
  ReedSolomon<Field, SlowConvolutionFactory> r_slow(N, M, f, slow_factory);
  r_slow.interpolate(&L3[0]);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L3[i], L[i]);
  }

  std::vector<Elt> L4(M);
  for (size_t i = 0; i < N; ++i) {
    L4[i] = L[i];
  }
  CrtConvolutionFactory crt_factory(f);
  ReedSolomon<Field, CrtConvolutionFactory> r_crt(N, M, f, crt_factory);
  r_crt.interpolate(&L4[0]);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L4[i], L[i]);
  }
}

TEST(ReedSolomonTest, ReedSolomon) {
  one_field_reed_solomon(omegaf, omegaf_order, F);
  one_field_reed_solomon(omegag, omegag_order, G);
}

TEST(Reed_Solomon, Product) {
  // Test that the product of two polynomials of degree < SMALL
  // has degree < 2*SMALL-1.  Start with A[SMALL] and B[SMALL],
  // extend to SMALLC = 2*SMALL-1 points and compute C[i] = A[i] * B[i];
  // extend to LARGE points and verify that C[i] == A[i] * B[i]
  // for all i.  The test fails for SMALLC < 2*SMALL-1, as expected.
  constexpr size_t small = 17, large = 50, smallc = 2 * small - 1;
  using Elt = Fp<1>::Elt;
  using FFTConvolutionFactory = FFTConvolutionFactory<Fp<1>>;
  using ReedSolomon = ReedSolomon<Fp<1>, FFTConvolutionFactory>;

  Elt omega = omegag;
  uint64_t omega_order = omegag_order;
  Elt A[large], B[large];
  Bogorng<Fp<1>> rng(&G);
  for (size_t i = 0; i < small; ++i) {
    A[i] = rng.next();
    B[i] = rng.next();
  }

  FFTConvolutionFactory factory(G, omega, omega_order);
  ReedSolomon r(small, large, G, factory);
  r.interpolate(A);
  r.interpolate(B);

  Elt C[large];
  for (size_t i = 0; i < smallc; ++i) {
    C[i] = G.mulf(A[i], B[i]);
  }
  ReedSolomon rc(smallc, large, G, factory);
  rc.interpolate(C);
  for (size_t i = 0; i < large; ++i) {
    EXPECT_EQ(G.mulf(A[i], B[i]), C[i]);
  }
}

TEST(ReedSolomonTest, SlowConvolutionFactory) {
  using Field = Fp<4>;
  using Elt = typename Field::Elt;
  using Interpolation = Interpolation<N, Field>;
  using SlowConvolutionFactory = SlowConvolutionFactory<Field>;
  using ReedSolomon = ReedSolomon<Field, SlowConvolutionFactory>;
  using Poly = Poly<N, Field>;

  Bogorng<Field> rng(&F);
  Poly P;

  // arbitrary coefficients
  for (size_t i = 0; i < N; ++i) {
    P[i] = F.of_scalar(i * i * i + (i & 0xF) + (i ^ (i << 2)));
  }
  // lagrange basis, i.e., values at first m points
  Elt L[M];
  for (size_t i = 0; i < M; ++i) {
    Elt x = F.of_scalar(i);
    L[i] = Interpolation::eval_monomial(P, x, F);
  }
  Elt L2[M];
  for (size_t i = 0; i < N; ++i) {
    L2[i] = L[i];
  }
  SlowConvolutionFactory factory(F);
  ReedSolomon r(N, M, F, factory);
  r.interpolate(L2);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L2[i], L[i]);
  }
}

TEST(ReedSolomonTest, LowDegreePolynomial) {
  using Field = Fp<4>;
  using Elt = typename Field::Elt;
  using Interpolation = Interpolation<N, Field>;
  using FFTConvolutionFactory = FFTConvolutionFactory<Field>;
  using ReedSolomon = ReedSolomon<Field, FFTConvolutionFactory>;
  using Poly = Poly<N, Field>;

  Elt omega = omegaf;
  uint64_t omega_order = omegaf_order;
  Bogorng<Field> rng(&F);
  Poly P;

  // arbitrary coefficients
  for (size_t i = 0; i < N; ++i) {
    P[i] = F.of_scalar(i * i * i + (i & 0xF) + (i ^ (i << 2)));
  }
  // lagrange basis, i.e., values at first n+m points
  Elt L[M];
  for (size_t i = 0; i < M; ++i) {
    Elt x = F.of_scalar(i);
    L[i] = Interpolation::eval_monomial(P, x, F);
  }
  Elt L2[N + M];
  for (size_t i = 0; i < N; ++i) {
    L2[i] = L[i];
  }
  Elt L3[N + M];
  for (size_t i = 0; i < N + 10; ++i) {
    L3[i] = L[i];
  }
  FFTConvolutionFactory factory(F, omega, omega_order);
  ReedSolomonFactory<Field, FFTConvolutionFactory> rf(factory, F);
  auto r = rf.make(N, M);
  r->interpolate(L2);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L2[i], L[i]);
  }
  // Giving N + 10 points for a polynomial of degree only N-1
  ReedSolomon r2(N + 10, M, F, factory);
  r2.interpolate(L3);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L3[i], L[i]);
  }
}

TEST(ReedSolomonTest, FieldExtension) {
  using BaseField = Fp256<>;
  using BaseElt = BaseField::Elt;
  using ExtField = Fp2<BaseField>;
  using ExtElt = ExtField::Elt;

  const BaseField F0;        // base field
  const ExtField F_ext(F0);  // p^2 field extension

  using Interpolation = Interpolation<N, BaseField>;
  using FFTExtConvolutionFactory =
      FFTExtConvolutionFactory<BaseField, ExtField>;
  using ReedSolomon = ReedSolomon<BaseField, FFTExtConvolutionFactory>;
  using Poly = Poly<N, BaseField>;

  ExtElt omega = F_ext.of_string(
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802",
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908");
  uint64_t omega_order = 1ull << 31;
  Poly P;

  // arbitrary coefficients in base field
  for (size_t i = 0; i < N; ++i) {
    P[i] = F0.of_scalar(i * i * i + (i & 0xF) + (i ^ (i << 2)));
  }
  // lagrange basis, i.e., values at first n+m points
  BaseElt L[M];
  for (size_t i = 0; i < M; ++i) {
    BaseElt x = F0.of_scalar(i);
    L[i] = Interpolation::eval_monomial(P, x, F0);
  }
  BaseElt L2[N + M];
  for (size_t i = 0; i < N; ++i) {
    L2[i] = L[i];
  }

  FFTExtConvolutionFactory factory(F0, F_ext, omega, omega_order);
  ReedSolomon r = ReedSolomon(N, M, F0, factory);
  r.interpolate(L2);
  for (size_t i = 0; i < M; ++i) {
    EXPECT_EQ(L2[i], L[i]);
  }
}

// ==================== Benchmarking ====================

#define BENCHMARK_SETTINGS ->RangeMultiplier(4)->Range(1 << 10, 1 << 22)

// This benchmark template works for both standard fields and field extensions.
template <class BaseField, class FFT, class RS, const BaseField& f,
          const FFT& factory>
void BM_ReedSolomon(benchmark::State& state) {
  using Elt = typename BaseField::Elt;
  Bogorng<BaseField> rng(&f);
  size_t n = state.range(0);
  RS r = RS(n, n * 4, f, factory);
  std::vector<Elt> L2(n + n * 4);
  for (size_t i = 0; i < n; ++i) {
    L2[i] = rng.next();
  }
  for (auto _ : state) {
    r.interpolate(&L2[0]);
  }
}

// FP 128
using Fp128 = Fp128<true>;
using FFT_p128 = FFTConvolutionFactory<Fp128>;
using RS_p128 = ReedSolomon<Fp128, FFT_p128>;
const Fp128 fp128;
const auto kOmega128 =
    fp128.of_string("164956748514267535023998284330560247862");
const uint64_t kOmegaOrder128 = 1ull << 32;
const FFT_p128 fft_p128(fp128, kOmega128, kOmegaOrder128);

void BM_ReedSolomonFp128(benchmark::State& state) {
  BM_ReedSolomon<Fp128, FFT_p128, RS_p128, fp128, fft_p128>(state);
}
BENCHMARK(BM_ReedSolomonFp128) BENCHMARK_SETTINGS;

// FP 64
using Fp64 = Fp<1>;
using FFT_p64 = FFTConvolutionFactory<Fp64>;
using RS_p64 = ReedSolomon<Fp64, FFT_p64>;
const Fp64 fp64("18446744069414584321");
const auto kOmega64 = fp64.of_string("2752994695033296049");
const uint64_t kOmegaOrder64 = 1ull << 29;
const FFT_p64 fft_p64(fp64, kOmega64, kOmegaOrder64);

void BM_ReedSolomonFp64(benchmark::State& state) {
  BM_ReedSolomon<Fp64, FFT_p64, RS_p64, fp64, fft_p64>(state);
}
BENCHMARK(BM_ReedSolomonFp64) BENCHMARK_SETTINGS;

// FP p256^2
using Fp256 = Fp256<>;
using Fp256_2 = Fp2<Fp256>;
using FFT_p256_2 = FFTExtConvolutionFactory<Fp256, Fp256_2>;
using RS_p256_2 = ReedSolomon<Fp256, FFT_p256_2>;
const Fp256 fp256;
const Fp256_2 fp256_2(fp256);
const FFT_p256_2 fft_p256_2(
    fp256, fp256_2,
    fp256_2.of_string("11264922414641028187350045760969025837301884043048940872"
                      "9223714171582664680802",
                      "84087994358540907695740461427818660560182168997182378749"
                      "313018254450460212908"),
    1ull << 31);

void BM_ReedSolomonFp256(benchmark::State& state) {
  BM_ReedSolomon<Fp256, FFT_p256_2, RS_p256_2, fp256, fft_p256_2>(state);
}

BENCHMARK(BM_ReedSolomonFp256) BENCHMARK_SETTINGS;

using CRT_p256 = CrtConvolutionFactory<CRT256<Fp256>, Fp256>;
using RS_CRT_p256 = ReedSolomon<Fp256, CRT_p256>;
const CRT_p256 crt_factory(fp256);

void BM_ReedSolomonFp256_crt(benchmark::State& state) {
  BM_ReedSolomon<Fp256, CRT_p256, RS_CRT_p256, fp256, crt_factory>(state);
}
BENCHMARK(BM_ReedSolomonFp256_crt) BENCHMARK_SETTINGS;

// 384-bit prime examples
// Use a prime that has a root of unity to compare against CRT.
using Fp6 = Fp<6, true>;
using FFT_w6 = FFTConvolutionFactory<Fp6>;
using RS_w6 = ReedSolomon<Fp6, FFT_w6>;
const Fp6 fp6(
    "20037974874267939960898896867684052278357888070333354909979956374824637627"
    "743258099255609959785846902476153458524161");
const auto kOmega6 = fp6.of_string(
    "50647606193563528288433715408802192282898918225577021459322655193419480990"
    "14652144667694099245156866923045442095606");
const uint64_t kOmegaOrder6 = 1ull << 22;
const FFT_w6 fft_w6(fp6, kOmega6, kOmegaOrder6);

void BM_RS384_native(benchmark::State& state) {
  BM_ReedSolomon<Fp6, FFT_w6, RS_w6, fp6, fft_w6>(state);
}
BENCHMARK(BM_RS384_native) BENCHMARK_SETTINGS;

// Same prime using CRT.
using CRT_p6 = CrtConvolutionFactory<CRT384<Fp6>, Fp6>;
using RS_CRT_p6 = ReedSolomon<Fp6, CRT_p6>;
const CRT_p6 crt_p6_factory(fp6);

void BM_RS384_crt(benchmark::State& state) {
  BM_ReedSolomon<Fp6, CRT_p6, RS_CRT_p6, fp6, crt_p6_factory>(state);
}
BENCHMARK(BM_RS384_crt) BENCHMARK_SETTINGS;

// 521-bit prime examples
// Use a prime that has a root of unity to compare against CRT.
using Fp9 = Fp<9, true>;
using FFT_w9 = FFTConvolutionFactory<Fp9>;
using RS_w9 = ReedSolomon<Fp9, FFT_w9>;

const Fp9 fp9(
    "32079476204984456963893996693749287914273772187064638495748042644433982545"
    "37419754756860742716602395683304244565676779070886473574346574476927946442"
    "026254337");
const auto kOmega9 = fp9.of_string(
    "31823443021031919081147483961203288919826765761971511088433594166437381726"
    "07399657243575079979889297218330863250710223139208683093312148113827665536"
    "113183520");
const FFT_w9 fft_w9(fp9, kOmega9, 1ull << 22);

void BM_RS521_native(benchmark::State& state) {
  BM_ReedSolomon<Fp9, FFT_w9, RS_w9, fp9, fft_w9>(state);
}
BENCHMARK(BM_RS521_native) BENCHMARK_SETTINGS;

// Same prime using CRT.
using CRT_p9 = CrtConvolutionFactory<CRT384<Fp9>, Fp9>;
using RS_CRT_p9 = ReedSolomon<Fp9, CRT_p9>;
const CRT_p9 crt_p9_factory(fp9);

void BM_RS521_crt(benchmark::State& state) {
  BM_ReedSolomon<Fp9, CRT_p9, RS_CRT_p9, fp9, crt_p9_factory>(state);
}
BENCHMARK(BM_RS521_crt) BENCHMARK_SETTINGS;

}  // namespace
}  // namespace proofs
