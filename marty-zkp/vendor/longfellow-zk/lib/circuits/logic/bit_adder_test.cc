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

#include "circuits/logic/bit_adder.h"

#include <stddef.h>


#include "algebra/fp_p128.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void test_bit_adder() {
  constexpr size_t w = 4;
  constexpr size_t mask = (1 << w) - 1;
  const Field F;

  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using BV = typename Logic::template bitvec<w>;
  for (size_t a = 0; a < (1 << w); ++a) {
    for (size_t b = 0; b < (1 << w); ++b) {
      for (size_t c = 0; c < (1 << w); ++c) {
        for (size_t s = 0; s < (1 << w); ++s) {
          const EvalBackend ebk(F, /* panic_on_assertion_failure=*/false);
          const Logic L(&ebk, F);
          BV ea = L.template vbit<w>(a);
          BV eb = L.template vbit<w>(b);
          BV ec = L.template vbit<w>(c);
          BV es = L.template vbit<w>(s);

          BitAdder<Logic, w> BA(L);
          BA.assert_eqmod(es, BA.add({ea, eb, ec}), 3);
          EXPECT_EQ(ebk.assertion_failed(), (((a + b + c) ^ s) & mask) != 0);
        }
      }
    }
  }
}

TEST(BitAdder, Fields) {
  test_bit_adder<GF2_128<>>();
  test_bit_adder<Fp128<>>();
}

}  // namespace
}  // namespace proofs
