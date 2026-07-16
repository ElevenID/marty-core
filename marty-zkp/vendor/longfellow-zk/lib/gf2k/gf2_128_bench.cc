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

#include <cstddef>

#include "gf2k/gf2_128.h"
#include "third_party/benchmark/include/benchmark/benchmark.h"

namespace proofs {
using Field = GF2_128<>;
using Elt = Field::Elt;
static const Field F;

void BM_gf2_128(benchmark::State& state) {
  Elt x = F.of_scalar(2);
  Elt y[1000];
  for (auto _ : state) {
    benchmark::DoNotOptimize(&x);
    for (size_t j = 0; j < 1000; ++j) {
      y[j] = x;
      x = F.mulf(x, x);
    }
    for (size_t i = 0; i < 1000 * 1000; ++i) {
      for (size_t j = 0; j < 1000; ++j) {
        y[j] = F.mulf(y[j], x);
      }
      x = F.mulf(x, x);
    }
    for (size_t j = 0; j < 1000; ++j) {
      x = F.mulf(y[j], x);
    }
  }
}
BENCHMARK(BM_gf2_128);
}  // namespace proofs

BENCHMARK_MAIN();
