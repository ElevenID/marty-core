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
#include <vector>

#include "gf2k/gf2_128.h"
#include "gf2k/lch14.h"
#include "third_party/benchmark/include/benchmark/benchmark.h"

namespace proofs {
using Field = GF2_128<5>;  // use 32-bit subfield for large FFTs
using Elt = Field::Elt;
static const Field F;
static const LCH14<Field> FFT(F);

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

BENCHMARK(BM_LCH14_FFT)->DenseRange(2, 20);

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

BENCHMARK(BM_LCH14_IFFT)->DenseRange(2, 20);

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

BENCHMARK(BM_LCH14_BidirectionalFFT)->DenseRange(2, 20);

}  // namespace proofs

BENCHMARK_MAIN();
