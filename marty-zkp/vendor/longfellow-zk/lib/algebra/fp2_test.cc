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

#include "algebra/fp2.h"

#include <stddef.h>

#include <array>
#include <cstdint>
#include <vector>

#include "algebra/fft.h"
#include "algebra/fp.h"
#include "algebra/fp_p256.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
template <class Field>
struct tests {
  using Elt = typename Field::Elt;

  static void arithmetic(const Field& F) {
    EXPECT_EQ(F.two(), F.addf(F.one(), F.one()));
    EXPECT_EQ(F.one(), F.addf(F.two(), F.mone()));
    EXPECT_EQ(F.zero(), F.addf(F.one(), F.mone()));
    EXPECT_EQ(F.one(), F.addf(F.half(), F.half()));
    EXPECT_TRUE(F.in_subfield(F.one()));
    EXPECT_TRUE(F.in_subfield(F.two()));
    EXPECT_TRUE(F.in_subfield(F.half()));

    size_t n = 8;
    for (size_t i0 = 0; i0 < n; ++i0) {
      for (size_t i1 = 0; i1 < n; ++i1) {
        Elt a = F.of_scalar_field(i0, i1);
        if (a != F.zero()) {
          Elt inva = F.invertf(a);
          EXPECT_EQ(F.mulf(a, inva), F.one());
        }
        if (i0 != 0 && i1 != 0) {
          EXPECT_FALSE(F.in_subfield(a));
        }
        for (size_t j0 = 0; j0 < n; ++j0) {
          for (size_t j1 = 0; j1 < n; ++j1) {
            Elt b = F.of_scalar_field(j0, j1);
            EXPECT_EQ(F.addf(a, b), F.addf(b, a));
            EXPECT_EQ(F.subf(F.addf(a, b), b), a);
            EXPECT_EQ(F.subf(a, b), F.addf(a, F.negf(b)));  // a - b = a + (-b)
            EXPECT_EQ(a, F.negf(F.negf(a)));
            EXPECT_EQ(F.mulf(a, b), F.mulf(b, a));
            EXPECT_EQ(F.addf(a, b), F.of_scalar_field(i0 + j0, i1 + j1));

            for (size_t k0 = 0; k0 < n; ++k0) {
              for (size_t k1 = 0; k1 < n; ++k1) {
                Elt c = F.of_scalar_field(k0, k1);
                EXPECT_EQ(F.addf(F.addf(a, b), c), F.addf(a, F.addf(b, c)));
                EXPECT_EQ(F.mulf(F.mulf(a, b), c), F.mulf(a, F.mulf(b, c)));
              }
            }
          }
        }
      }
    }
  }

  static Elt reroot(const Elt& omega_n, uint64_t n, uint64_t r,
                    const Field& F) {
    Elt omega_r = omega_n;
    while (r < n) {
      EXPECT_NE(omega_r, F.one());
      F.mul(omega_r, omega_r);
      r += r;
    }
    return omega_r;
  }

  static void root_of_unity(const Elt& omega_n, uint64_t n, const Field& F) {
    EXPECT_EQ(F.one(), reroot(omega_n, n, 1, F));
  }

  static void fft_impulse(const Elt& omega, uint64_t omega_order,
                          const Field& F) {
    size_t n = 1 << 11;
    std::vector<Elt> A(n);
    std::vector<Elt> B(n);
    std::vector<Elt> C(n);
    Elt k0 = F.of_scalar_field(33, 77);
    Elt k1 = F.of_scalar_field(41, 53);

    for (size_t i = 0; i < n; ++i) {
      A[i] = F.of_scalar(i == 0);
      B[i] = F.of_scalar_field(i + 33, i * i + i + 1);
      C[i] = F.addf(F.mulf(k0, A[i]), F.mulf(k1, B[i]));
    }

    FFT<Field>::fftb(A.data(), n, omega, omega_order, F);
    FFT<Field>::fftb(B.data(), n, omega, omega_order, F);
    FFT<Field>::fftb(C.data(), n, omega, omega_order, F);
    for (size_t i = 0; i < n; ++i) {
      EXPECT_EQ(C[i], F.addf(F.mulf(k0, A[i]), F.mulf(k1, B[i])));
    }
  }

  static void fft_shift(const Elt& omega, uint64_t omega_order,
                        const Field& F) {
    size_t n = 1 << 11;
    std::vector<Elt> A(n);
    std::vector<Elt> B(n);
    std::vector<Elt> C(n);
    Elt k0 = F.of_scalar_field(33, 77);
    Elt k1 = F.of_scalar_field(41, 53);

    Elt omega_n = reroot(omega, omega_order, n, F);

    for (size_t i = 0; i < n; ++i) {
      A[i] = F.of_scalar_field(17 * i + 2);
      B[i] = F.of_scalar_field(19 * i + 3);
    }
    for (size_t i = 0; i < n; ++i) {
      C[i] = F.addf(F.mulf(k0, A[(i + 1) % n]), F.mulf(k1, B[i]));
    }
    FFT<Field>::fftb(A.data(), n, omega, omega_order, F);
    FFT<Field>::fftb(B.data(), n, omega, omega_order, F);
    FFT<Field>::fftb(C.data(), n, omega, omega_order, F);
    Elt w = F.one();
    for (size_t i = 0; i < n; ++i) {
      EXPECT_EQ(F.addf(F.mulf(k0, A[i]), F.mulf(F.mulf(k1, B[i]), w)),
                F.mulf(C[i], w));
      F.mul(w, omega_n);
    }
  }

  static void bytes(const Field& F) {
    size_t n = 16;
    for (uint64_t i0 = 1; i0 < n; i0 *= 3) {
      for (uint64_t i1 = 1; i1 < n; i1 *= 2) {
        auto x = F.of_scalar_field(i0, i1);
        uint8_t bytes[Field::kBytes];
        F.to_bytes_field(bytes, x);
        auto y = F.of_bytes_field(bytes);
        EXPECT_TRUE(y.has_value());
        EXPECT_EQ(x, y);
      }
      auto x = F.of_scalar(i0);
      uint8_t bytes[Field::kSubFieldBytes];
      F.to_bytes_subfield(bytes, x);
      auto y = F.of_bytes_subfield(bytes);
      EXPECT_TRUE(y.has_value());
      EXPECT_EQ(x, y);
    }

    std::array<uint8_t, Field::kBytes> bad_bytes;
    bad_bytes.fill(0xff);
    auto x = F.of_bytes_field(bad_bytes.data());
    EXPECT_FALSE(x.has_value());
    auto sx = F.of_bytes_subfield(bad_bytes.data());
    EXPECT_FALSE(sx.has_value());

    // First half valid (0), second half invalid (0xff)
    std::array<uint8_t, Field::kBytes> partial_bad_bytes;
    partial_bad_bytes.fill(0);
    for (size_t i = Field::kSubFieldBytes; i < Field::kBytes; ++i) {
      partial_bad_bytes[i] = 0xff;
    }
    auto y = F.of_bytes_field(partial_bad_bytes.data());
    EXPECT_FALSE(y.has_value());

    auto string_elt = F.of_string("123");
    EXPECT_EQ(string_elt, F.of_scalar(123));
  }

  static void poly_evaluation_points(const Field& F) {
    const size_t N = F.f_.kNPolyEvaluationPoints;
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

  static void all(const Elt& omega_n, uint64_t n, const Field& F) {
    arithmetic(F);
    root_of_unity(omega_n, n, F);
    fft_impulse(omega_n, n, F);
    fft_shift(omega_n, n, F);
    bytes(F);
    poly_evaluation_points(F);
  }
};

TEST(Fp2, All) {
  using Field0 = Fp<1>;
  {
    // 2^61-1
    const Field0 F0("2305843009213693951");
    using Field = Fp2<Field0>;
    const Field F(F0);
    const auto omega = F.of_scalar_field(1033321771269002680ull, 2147483648ull);
    const uint64_t omega_order = 1ull << 62;
    tests<Field>::all(omega, omega_order, F);
  }
  {
    // goldilocks
    const Field0 F0("18446744069414584321");
    const auto nonresidue = F0.of_scalar(7);  // known
    using Field = Fp2<Field0, false>;
    const Field F(F0, nonresidue);
    const auto omega = F.of_scalar_field(1753635133440165772ull, 0);
    const uint64_t omega_order = 1ull << 32;
    tests<Field>::all(omega, omega_order, F);
  }
  {
    // F_p256
    const Fp256<true> F0;
    using Field = Fp2<Fp256<true>>;
    const Field F(F0);
    static constexpr char kRootX[] =
        "1126492241464102818735004576096902583730188404304894087292237141715826"
        "64680802";
    static constexpr char kRootY[] =
        "8408799435854090769574046142781866056018216899718237874931301825445046"
        "0212908";
    const auto omega = F.of_string(kRootX, kRootY);
    const uint64_t omega_order = 1ull << 31;
    tests<Field>::all(omega, omega_order, F);
  }
}

// ==================== Benchmarking ====================
void BM_p2562_add(benchmark::State& state) {
  const Fp256<true> F0;
  using Field = Fp2<Fp256<true>>;
  const Field F(F0);
  static constexpr char kRootX[] =
      "1126492241464102818735004576096902583730188404304894087292237141715826"
      "64680802";
  static constexpr char kRootY[] =
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908";
  auto omega = F.of_string(kRootX, kRootY);

  for (auto _ : state) {
    auto t = F.addf(omega, omega);
    benchmark::DoNotOptimize(t);
  }
}

BENCHMARK(BM_p2562_add);

void BM_p2562_mul(benchmark::State& state) {
  const Fp256<true> F0;
  using Field = Fp2<Fp256<true>>;
  const Field F(F0);
  static constexpr char kRootX[] =
      "1126492241464102818735004576096902583730188404304894087292237141715826"
      "64680802";
  static constexpr char kRootY[] =
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908";
  auto a = F.of_string(kRootX, kRootY);
  for (auto _ : state) {
    auto b = F.mulf(a, a);
    benchmark::DoNotOptimize(b);
  }
}

BENCHMARK(BM_p2562_mul);

}  // namespace
}  // namespace proofs
