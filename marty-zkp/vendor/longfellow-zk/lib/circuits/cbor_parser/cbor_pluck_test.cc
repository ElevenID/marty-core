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

#include "circuits/cbor_parser/cbor_pluck.h"

#include <stddef.h>

#include "algebra/fp.h"
#include "circuits/logic/bit_plucker_constants.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void pluck_test(const Field &F) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;

  constexpr size_t NJ = 7;
  constexpr size_t N = 2 * (NJ + 1);
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const CborPlucker<Logic, NJ> P(L);

  for (size_t i = 0; i < N; ++i) {
    auto gotb = P.pluckb(L.konst(bit_plucker_point<Field, N>()(i, F)));
    auto gotj = P.pluckj(L.konst(bit_plucker_point<Field, N>()(i, F)));
    EXPECT_EQ(L.eval(gotb), L.konst(i & 1));
    for (size_t j = 0; j < NJ; ++j) {
      EXPECT_EQ(L.eval(gotj[j]), L.konst((i >> 1) == j));
    }
  }
}

TEST(CborPluck, PluckPrimeField) { pluck_test(Fp<1>("18446744073709551557")); }

TEST(CborPluck, PluckBinaryField) { pluck_test(GF2_128<>()); }

}  // namespace
}  // namespace proofs
