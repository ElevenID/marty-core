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

#include "gf2k/lch14_reed_solomon.h"

#include <cstddef>
#include <vector>

#include "algebra/bogorng.h"
#include "gf2k/gf2_128.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = GF2_128<5>;
using Elt = Field::Elt;
static const Field F;

// slow evaluation in the monomial basis
static Elt eval_monomial(size_t n, const Elt M[/*n*/], const Elt& x) {
  Elt e{};

  for (size_t i = n; i-- > 0;) {
    e = F.addf(M[i], F.mulf(e, x));
  }
  return e;
}

TEST(LCH14, ReedSolomon) {
  std::vector<size_t> test_m = {1, 7, 8, 9, 63, 64, 65, 99, 128};
  LCH14ReedSolomonFactory<Field> rs_factory(F);

  for (size_t m : test_m) {
    for (size_t n = 1; n < m; ++n) {
      auto rs = rs_factory.make(n, m);
      std::vector<Elt> M(n);  // monomial basis
      std::vector<Elt> Y(m);

      for (size_t i = 0; i < n; ++i) {
        M[i] = F.of_scalar(i * i + 42 + (m + 11) * (n + 22));
      }

      // produce N points
      for (size_t i = 0; i < n; ++i) {
        Y[i] = eval_monomial(n, &M[0], F.of_scalar(i));
      }

      rs->interpolate(&Y[0]);

      for (size_t i = 0; i < m; ++i) {
        EXPECT_EQ(Y[i], eval_monomial(n, &M[0], F.of_scalar(i)));
      }
    }
  }
}
}  // namespace

namespace bench {
void BM_ReedSolomon_gf128(benchmark::State& state) {
  size_t n = state.range(0);
  if (4 * n < 1 << 16) {
    using Field = GF2_128<4>;
    using Elt = Field::Elt;
    static const Field F;
    LCH14ReedSolomonFactory<Field> rs_factory(F);
    Bogorng<Field> rng(&F);
    auto rs = rs_factory.make(n, n * 4);

    std::vector<Elt> L2(n + n * 4);
    for (size_t i = 0; i < n; ++i) {
      L2[i] = rng.next();
    }
    for (auto _ : state) {
      rs->interpolate(&L2[0]);
    }
  } else {
    using Field = GF2_128<5>;
    using Elt = Field::Elt;
    static const Field F;
    LCH14ReedSolomonFactory<Field> rs_factory(F);
    Bogorng<Field> rng(&F);
    auto rs = rs_factory.make(n, n * 4);

    std::vector<Elt> L2(n + n * 4);
    for (size_t i = 0; i < n; ++i) {
      L2[i] = rng.next();
    }
    for (auto _ : state) {
      rs->interpolate(&L2[0]);
    }
  }
}

BENCHMARK(BM_ReedSolomon_gf128)->RangeMultiplier(4)->Range(1 << 10, 1 << 20);

}  // namespace bench
}  // namespace proofs
