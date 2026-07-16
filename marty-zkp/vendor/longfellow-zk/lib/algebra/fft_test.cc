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

#include "algebra/fft.h"

#include <stddef.h>

#include <cstdint>
#include <vector>

#include "algebra/bogorng.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/fp_p128.h"
#include "algebra/fp_p256.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

typedef Fp<4> Field;
static const Field F(
    "21888242871839275222246405745257275088548364400416034343698204186575808495"
    "617");
typedef Field::Elt Elt;
Bogorng<Field> rng(&F);

// root of unity in F
Elt omega = F.of_string(
    "19103219067921713944291392827692070036145651957329286315305642004821462161"
    "904");
size_t omega_order = 1 << 28;
constexpr size_t N = 1 << 16;

static Elt reroot(const Elt& omega_n, size_t n, size_t r, const Field& FF) {
  Elt omega_r = omega_n;
  while (r < n) {
    FF.mul(omega_r, omega_r);
    r += r;
  }
  return omega_r;
}

TEST(FFT, Inverse) {
  size_t n = N;
  std::vector<Elt> A(n);
  for (size_t i = 0; i < n; ++i) {
    A[i] = rng.next();
  }
  std::vector<Elt> B(A);
  FFT<Field>::fftf(&A[0], n, omega, omega_order, F);
  FFT<Field>::fftb(&A[0], n, omega, omega_order, F);
  for (size_t i = 0; i < n; ++i) {
    F.mul(A[i], F.invertf(F.of_scalar(n)));
  }
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(A[i], B[i]);
  }
}

TEST(FFT, Linear) {
  size_t n = N;
  std::vector<Elt> A(n);
  std::vector<Elt> B(n);
  std::vector<Elt> C(n);
  auto k0 = rng.next();
  auto k1 = rng.next();
  for (size_t i = 0; i < n; ++i) {
    A[i] = rng.next();
    B[i] = rng.next();
    C[i] = F.addf(F.mulf(k0, A[i]), F.mulf(k1, B[i]));
  }
  FFT<Field>::fftf(&A[0], n, omega, omega_order, F);
  FFT<Field>::fftf(&B[0], n, omega, omega_order, F);
  FFT<Field>::fftf(&C[0], n, omega, omega_order, F);
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(C[i], F.addf(F.mulf(k0, A[i]), F.mulf(k1, B[i])));
  }
}

TEST(FFT, Impulse) {
  size_t n = N;
  std::vector<Elt> A(n);
  std::vector<Elt> B(n);
  std::vector<Elt> C(n);
  Elt k0 = rng.next();
  Elt k1 = rng.next();

  for (size_t i = 0; i < n; ++i) {
    A[i] = i == 0 ? F.zero() : F.one();
    B[i] = rng.next();
    C[i] = F.addf(F.mulf(k0, A[i]), F.mulf(k1, B[i]));  // k0 * A[i] + k1 * B[i]
  }

  FFT<Field>::fftf(&A[0], n, omega, omega_order, F);
  FFT<Field>::fftf(&B[0], n, omega, omega_order, F);
  FFT<Field>::fftf(&C[0], n, omega, omega_order, F);
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(C[i], F.addf(F.mulf(k0, A[i]), F.mulf(k1, B[i])));
  }
}

TEST(FFT, RootOfUnity) {
  Elt one = reroot(omega, omega_order, 1, F);
  Elt one1 = F.one();
  EXPECT_EQ(one, one1);
}

TEST(FFT, Shift) {
  size_t n = N;
  std::vector<Elt> A(n);
  std::vector<Elt> B(n);
  std::vector<Elt> C(n);
  Elt omega_n = reroot(omega, omega_order, n, F);
  Elt k0 = rng.next();
  Elt k1 = rng.next();

  for (size_t i = 0; i < n; ++i) {
    A[i] = rng.next();
    B[i] = rng.next();
  }
  for (size_t i = 0; i < n; ++i) {
    // k0 * A[(i + 1) % n] + k1 * B[i]
    C[i] = F.addf(F.mulf(k0, A[(i + 1) % n]), F.mulf(k1, B[i]));
  }

  FFT<Field>::fftb(&A[0], n, omega, omega_order, F);
  FFT<Field>::fftb(&B[0], n, omega, omega_order, F);
  FFT<Field>::fftb(&C[0], n, omega, omega_order, F);
  Elt w = F.one();
  EXPECT_EQ(w, reroot(omega_n, n, 1, F));
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(F.addf(F.mulf(k0, A[i]), F.mulf(F.mulf(k1, B[i]), w)),
              F.mulf(w, C[i]));  // k0 * A[i] + k1 * B[i] * w =  C[i] * w
    F.mul(w, omega_n);
  }
}
}  // namespace

// ================ Benchmarking ==============================================

// benchmark the FFT over a P256^2 with a real root of unity
namespace bench {
void BM_FFT_Fp256_2(benchmark::State& state) {
  using BaseField = Fp256<true>;
  using Field = Fp2<BaseField>;

  using Elt = Field::Elt;
  const BaseField F0;
  const Field F(F0);
  const Elt OMEGA31 = F.of_string(
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802",
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908");
  Bogorng<BaseField> rng(&F0);
  size_t N = state.range(0);
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = F.of_scalar(rng.next());
  }
  for (auto _ : state) {
    FFT<Field>::fftb(&A[0], N, OMEGA31, 1u << 31, F);
  }
}
BENCHMARK(BM_FFT_Fp256_2)
    ->RangeMultiplier(4)
    ->Range(1024, (1 << 22));

void BM_FFT_Fp128(benchmark::State& state) {
  using Field = Fp128<>;
  using Elt = Field::Elt;
  Field F;
  Bogorng<Field> rng(&F);
  // bogus root of unit, doesn't matter for benchmark purposes since
  // we are transforming zeroes anyway
  auto omega = F.two();
  size_t N = state.range(0);
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = rng.next();
  }
  for (auto _ : state) {
    FFT<Field>::fftb(&A[0], N, omega, omega_order, F);
  }
}

BENCHMARK(BM_FFT_Fp128)
    ->RangeMultiplier(4)
    ->Range(1024, (1 << 22));

void BM_FFT_F64_2(benchmark::State& state) {
  using BaseField = Fp<1>;
  using Field = Fp2<BaseField>;

  const BaseField F("18446744069414584321");
  const Field F2(F);
  using Elt = Field::Elt;
  static constexpr char kSmallRoot[] = "2752994695033296049";
  static constexpr uint64_t kSmallOrder = 1ull << 32;

  const Elt omega = F2.of_string(kSmallRoot);
  Bogorng<BaseField> rng(&F);

  size_t N = state.range(0);
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = F2.of_scalar(rng.next());
  }

  for (auto _ : state) {
    FFT<Field>::fftb(&A[0], N, omega, kSmallOrder, F2);
  }
}

BENCHMARK(BM_FFT_F64_2)
    ->RangeMultiplier(4)
    ->Range(1024, (1 << 22));

void BM_FFT_F64(benchmark::State& state) {
  using Field = Fp<1>;
  const Field F("18446744069414584321");
  using Elt = Field::Elt;
  static constexpr char kSmallRoot[] = "2752994695033296049";
  static constexpr uint64_t kSmallOrder = 1ull << 32;
  const Elt omega = F.of_string(kSmallRoot);
  Bogorng<Field> rng(&F);

  size_t N = state.range(0);
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = rng.next();
  }

  for (auto _ : state) {
    FFT<Field>::fftb(&A[0], N, omega, kSmallOrder, F);
  }
}

BENCHMARK(BM_FFT_F64)
    ->RangeMultiplier(4)
    ->Range(1024, (1 << 22));

}  // namespace bench
}  // namespace proofs
