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

#include "algebra/fft_interpolation.h"

#include <stddef.h>

#include <vector>

#include "algebra/blas.h"
#include "algebra/bogorng.h"
#include "algebra/fft.h"
#include "algebra/fp.h"
#include "algebra/fp2.h"
#include "algebra/fp_p256.h"
#include "algebra/permutations.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

typedef Fp<4> Field;
static const Field F(
    "21888242871839275222246405745257275088548364400416034343698204186575808495"
    "617");
typedef Field::Elt Elt;

// root of unity in F
Elt omega = F.of_string(
    "19103219067921713944291392827692070036145651957329286315305642004821462161"
    "904");
size_t omega_order = 1 << 28;

TEST(FFTInterpolation, Simple) {
  Bogorng<Field> rng(&F);
  for (size_t n = 1; n <= 32; n *= 2) {
    std::vector<Elt> A(n);
    std::vector<Elt> B(n);

    for (size_t i = 0; i < n; ++i) {
      A[i] = B[i] = rng.next();
    }
    FFT<Field>::fftf(&B[0], n, omega, omega_order, F);

    // FFTInterpolation expects A to be in bit-reversed order
    Permutations<Elt>::bitrev(&A[0], n);

    for (size_t k = 0; k <= n; ++k) {
      for (size_t b0 = 0; b0 < n; ++b0) {
        std::vector<Elt> CA(n, F.zero());
        std::vector<Elt> CB(n, F.zero());
        for (size_t i = 0; i < k; ++i) {
          CA[i] = A[i];
        }
        for (size_t i = b0; i < b0 + (n - k); ++i) {
          CB[i % n] = B[i % n];
        }

        FFTInterpolation<Field>::interpolate(n, &CA[0], &CB[0], k, b0, omega,
                                             omega_order, F);

        for (size_t i = 0; i < n; ++i) {
          EXPECT_EQ(A[i], CA[i]);
          EXPECT_EQ(B[i], CB[i]);
        }
      }
    }
  }
}

TEST(FFTInterpolation, Product) {
  // The product of two extensions of length d should
  // be an extension of length 2d
  Bogorng<Field> rng(&F);

  for (size_t n = 2; n <= 32; n *= 2) {
    for (size_t d = 1; d + d < n; ++d) {
      std::vector<Elt> A(n, F.zero());
      std::vector<Elt> B(n, F.zero());
      std::vector<Elt> C(n, F.zero());
      std::vector<Elt> Z(n);

      for (size_t i = 0; i < d; ++i) {
        A[i] = rng.next();
        B[i] = rng.next();
      }

      // extend A and B
      Blas<Field>::clear(n, &Z[0], 1, F);
      FFTInterpolation<Field>::interpolate(n, &A[0], &Z[0], d, d, omega,
                                           omega_order, F);
      Blas<Field>::clear(n, &Z[0], 1, F);
      FFTInterpolation<Field>::interpolate(n, &B[0], &Z[0], d, d, omega,
                                           omega_order, F);

      for (size_t i = 0; i < 2 * d - 1; ++i) {
        C[i] = F.mulf(A[i], B[i]);
      }
      Blas<Field>::clear(n, &Z[0], 1, F);
      FFTInterpolation<Field>::interpolate(n, &C[0], &Z[0], 2 * d - 1,
                                           2 * d - 1, omega, omega_order, F);

      for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(C[i], F.mulf(A[i], B[i]));
      }

      // for good measure, test that all possible extensions of A
      // produce A again
      for (size_t k = d; k < n; ++k) {
        std::vector<Elt> A1(n, F.zero());
        Blas<Field>::copy(k, &A1[0], 1, &A[0], 1);

        Blas<Field>::clear(n, &Z[0], 1, F);
        FFTInterpolation<Field>::interpolate(n, &A1[0], &Z[0], k, k, omega,
                                             omega_order, F);

        for (size_t i = 0; i < n; ++i) {
          EXPECT_EQ(A[i], A1[i]);
        }
      }
    }
  }
}
}  // namespace

namespace bench {
// benchmark the FFT over a P256^2 with a real root of unity
void BM_FFTInterpolationFp2(benchmark::State& state) {
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
  std::vector<Elt> B(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = F.of_scalar(rng.next());
    B[i] = F.of_scalar(rng.next());
  }
  for (auto _ : state) {
    FFTInterpolation<Field>::interpolate(N, &A[0], &B[0], N / 2, 0, OMEGA31,
                                         1u << 31, F);
  }
}
BENCHMARK(BM_FFTInterpolationFp2)->RangeMultiplier(4)->Range(1024, (1 << 22));

}  // namespace bench
}  // namespace proofs
