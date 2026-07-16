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

#include "circuits/logic/unary.h"

#include <stddef.h>

#include <vector>

#include "algebra/fp.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void one_test(const Field& F) {
  using EvaluationBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvaluationBackend>;
  using BitW = typename Logic::BitW;

  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  const Unary<Logic> U(L);

  constexpr size_t W = 6;
  using BV = typename Logic::template bitvec<W>;
  size_t n = 1u << W;

  for (size_t j = 0; j < n; ++j) {
    std::vector<BitW> EQ(n);
    std::vector<BitW> LT(n);
    BV jj = L.template vbit<W>(j);

    U.eq(n, EQ.data(), jj);
    U.lt(n, LT.data(), jj);
    for (size_t i = 0; i < n; ++i) {
      EXPECT_EQ(L.eval(EQ[i]), L.konst(i == j));
      EXPECT_EQ(L.eval(LT[i]), L.konst(i < j));
    }
  }
}

TEST(Unary, PrimeField) { one_test(Fp<1>("18446744073709551557")); }
TEST(Unary, BinaryField) { one_test(GF2_128<>()); }

}  // namespace
}  // namespace proofs
