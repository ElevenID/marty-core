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

#include "circuits/logic/unary_plucker.h"

#include <stddef.h>

#include "algebra/fp.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/unary_plucker_constants.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void pluck_test(const Field& F) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;

  constexpr size_t NJ = 7;
  constexpr size_t N = NJ + 1;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const UnaryPlucker<Logic, NJ> P(L);

  for (size_t i = 0; i < N; ++i) {
    auto got = P.pluck(L.konst(unary_plucker_point<Field, NJ>()(i, F)));
    for (size_t j = 0; j < NJ; ++j) {
      EXPECT_EQ(L.eval(got[j]), L.konst(i == j));
    }
  }
}

TEST(UnaryPluck, PluckPrimeField) { pluck_test(Fp<1>("18446744073709551557")); }

TEST(UnaryPluck, PluckBinaryField) { pluck_test(GF2_128<>()); }

}  // namespace
}  // namespace proofs
