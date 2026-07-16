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

#include "gf2k/lch14.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "algebra/interpolation.h"
#include "algebra/poly.h"
#include "gf2k/gf2_128.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = GF2_128<5>;
using Elt = Field::Elt;
static const Field F;
static const LCH14<Field> FFT(F);

// The "subspace vanishing polynomial"
//
//   W_i(X) = PROD_{u \in U_i} (X − u)
//
// where we axiomatically identify
//    U_i = { f_.of_scalar(j) : 0 <= j < 2^i }

// slow reference implementation
static Elt WRef(size_t i, const Elt &x) {
  constexpr uint64_t uno = 1;  // for the uint64_t type
  Elt prod = F.one();
  for (size_t j = 0; j < (uno << i); ++j) {
    F.mul(prod, F.subf(x, F.of_scalar(j)));
  }
  return prod;
}

static Elt WHatRef(size_t i, const Elt &x) {
  return F.mulf(WRef(i, x), F.invertf(WRef(i, F.beta(i))));
}

TEST(LCH14, WAdditivity) {
  size_t r = 6;
  for (size_t i = 0; i < r; ++i) {
    for (size_t x = 0; x < (1 << r); ++x) {
      Elt xx = F.of_scalar(x);
      Elt wx = WRef(i, xx);

      // W is supposed to vanish on the i-dimensional
      // subspace and nowhere else:
      if (x < (1 << i)) {
        EXPECT_EQ(wx, F.zero());
      } else {
        EXPECT_NE(wx, F.zero());
      }

      // [LCH14 Lemma 1] W(x + y) = W(x) + W(y)
      for (size_t y = 0; y < (1 << r); ++y) {
        Elt yy = F.of_scalar(y);
        EXPECT_EQ(WRef(i, F.addf(xx, yy)), F.addf(WRef(i, xx), WRef(i, yy)));
      }
    }
  }
}

// We use the identity
//
//    W_{i+1}(X) = W_i(X)(W_i(X)+W_i(\beta_i))
//
// See Shuhong Gao and Todd Mateer, "Additive Fast Fourier Transforms
// over Finite Fields", who credit [Cantor 1989].  The same formula is
// used in twiddle.rs in the Binius source code.  See also Todd
// D. Mateer, "Fast Fourier Transform Algorithms with Applications,"
// PhD Dissertation, Theorem 15 for an extended discussion.
//
// Proof: Because W is zero over the subspace, we have
//         W_{i+1}(X) = W_i(X) * W_i(X + \beta_i)
// Because W(X+Y) = W(X) + W(Y), we have
// W_i(X + \beta_i) = W_i(X) + W_i(\beta_i).
//
TEST(LCH14, WRecursion) {
  size_t r = 6;
  for (size_t i = 0; i < r; ++i) {
    Elt wibi = WRef(i, F.beta(i));
    for (size_t x = 0; x < (1 << r); ++x) {
      Elt xx = F.of_scalar(x);
      Elt wix = WRef(i, xx);
      Elt wi1x = WRef(i + 1, xx);
      EXPECT_EQ(wi1x, F.mulf(wix, F.addf(wix, wibi)));
    }
  }
}

TEST(LCH14, WHat) {
  // limit I because WHatRef() is exponential-time in I.
  for (size_t i = 0; i < std::min<size_t>(FFT.kSubFieldBits, 16); ++i) {
    for (size_t j = 0; j < FFT.kSubFieldBits; ++j) {
      EXPECT_EQ(FFT.WHat_DEBUG(i, j), WHatRef(i, F.beta(j)));
    }
  }
}

TEST(LCH14, Twiddle) {
  size_t l = std::min<size_t>(FFT.kSubFieldBits, 20);
  constexpr size_t uno = 1;
  std::vector<Elt> tw(uno << (l - 1));
  for (size_t i = 0; i < l; ++i) {
    FFT.twiddles(i, l, 0, &tw[0]);
    for (size_t u = 0; (u << (i + 1)) < (uno << l); ++u) {
      EXPECT_EQ(tw[u], FFT.twiddle(i, (u << (i + 1))));
    }
  }
}

TEST(LCH14, Interpolation) {
  constexpr size_t l = 5;
  constexpr size_t cosets = 7;
  constexpr size_t n = 1 << l;

  using Interp = Interpolation<n, Field>;
  using Poly = Poly<n, Field>;

  // check interpolations from all cosets CA to
  // all cosets CB
  for (size_t ca = 0; ca < cosets; ++ca) {
    Poly X, A;
    for (size_t i = 0; i < n; ++i) {
      X[i] = F.of_scalar(i + (ca << l));
      A[i] = F.of_scalar((i * (i + ca)) ^ 42);  // "random"
    }

    Poly Newton = Interp::newton_of_lagrange(A, X, F);

    FFT.IFFT(l, (ca << l), A.t_);

    for (size_t cb = 0; cb < cosets; ++cb) {
      Poly B = A;

      FFT.FFT(l, (cb << l), B.t_);
      for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(B[i], Interp::eval_newton(Newton, X,
                                            F.of_scalar(i + (cb << l)), F));
        EXPECT_TRUE(F.in_subfield(B[i]));
      }
    }
  }
}

TEST(LCH14, BidirectionalFFT) {
  constexpr size_t l = 10;
  constexpr size_t n = 1 << l;

  for (size_t k = 0; k <= n; ++k) {
    std::vector<Elt> C(n);  // "coefficients"
    std::vector<Elt> E(n);  // "evaluations"

    for (size_t i = 0; i < n; ++i) {
      E[i] = C[i] = F.of_scalar((i * i + 42) & 0xFFFFu);
    }

    // forward FFT from "coefficients" to evaluations, in-place
    FFT.FFT(l, 0, &E[0]);

    std::vector<Elt> B(n);

    // evaluations in the first half, "coefficients" in the second half
    for (size_t i = 0; i < n; ++i) {
      B[i] = (i < k) ? E[i] : C[i];
    }

    FFT.BidirectionalFFT(l, k, &B[0]);

    // Expect "coefficients" in the first half, evaluations in the second half
    for (size_t i = 0; i < n; ++i) {
      EXPECT_EQ(B[i], (i < k) ? C[i] : E[i]);
    }
  }
}

// =============================================================================
// Benchmarks
// =============================================================================

void BM_LCH14_FFT(benchmark::State& state) {
  size_t l = state.range(0);
  size_t N = 1 << l;
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = F.x();
  }

  for (auto _ : state) {
    FFT.FFT(l, /*coset=*/0, A.data());
  }
}

BENCHMARK(BM_LCH14_FFT)->DenseRange(10, 22, 2);


void BM_LCH14_IFFT(benchmark::State& state) {
  size_t l = state.range(0);
  size_t N = 1 << l;
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = F.x();
  }

  for (auto _ : state) {
    FFT.IFFT(l, /*coset=*/0, A.data());
  }
}

BENCHMARK(BM_LCH14_IFFT)->DenseRange(10, 22, 2);

void BM_LCH14_BidirectionalFFT(benchmark::State& state) {
  size_t l = state.range(0);
  size_t N = 1 << l;
  std::vector<Elt> A(N);
  for (size_t i = 0; i < N; ++i) {
    A[i] = F.x();
  }

  for (auto _ : state) {
    FFT.BidirectionalFFT(l, /*k=*/N - 1, A.data());
  }
}

BENCHMARK(BM_LCH14_BidirectionalFFT)->DenseRange(10, 22, 2);

}  // namespace
}  // namespace proofs
