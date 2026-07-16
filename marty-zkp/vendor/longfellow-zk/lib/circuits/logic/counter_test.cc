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

#include "circuits/logic/counter.h"

#include <stddef.h>

#include "algebra/fp_p128.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void test_counter() {
  const Field F;
  constexpr size_t w = 7;

  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using CounterL = Counter<Logic>;
  const EvalBackend ebk(F, /* panic_on_assertion_failure=*/false);
  const Logic L(&ebk, F);
  const CounterL CTR(L);

  for (size_t a = 0; a < (1 << w); ++a) {
    auto ca = CTR.as_counter(a);

    // Computing CA in the circuit from a bitvec
    // produces the same result as computing CA in the field
    {
      CTR.assert_eq(ca, CTR.as_counter(F.as_counter(a)));
      EXPECT_FALSE(ebk.assertion_failed());
      CTR.assert_eq(ca, CTR.as_counter(L.template vbit<w>(a)));
      EXPECT_FALSE(ebk.assertion_failed());
    }

    {
      auto eca = CTR.znz_indicator(ca);
      L.assert0(eca);
      EXPECT_EQ(ebk.assertion_failed(), (a != 0));

      // F.znz_indicator() and CTR.znz_indicator() must compute the
      // same thing
      L.assert_eq(eca, L.konst(F.znz_indicator(F.as_counter(a))));
      EXPECT_FALSE(ebk.assertion_failed());
    }

    {
      // assert0() works as expected
      CTR.assert0(ca);
      EXPECT_EQ(ebk.assertion_failed(), (a != 0));
    }

    {
      // minus one works as expected
      auto cam1 = CTR.add(ca, CTR.mone());
      CTR.assert0(cam1);
      EXPECT_EQ(ebk.assertion_failed(), (a != 1));

      if (a > 0) {
        auto want_cam1 = CTR.as_counter(a - 1);
        CTR.assert_eq(cam1, want_cam1);
        EXPECT_FALSE(ebk.assertion_failed());
      }
    }

    // addition works as expected
    for (size_t b = 0; b < (1 << w); ++b) {
      auto cb = CTR.as_counter(b);
      for (size_t s = 0; s < (2 << w); ++s) {
        auto cs = CTR.as_counter(s);

        auto ab = CTR.add(ca, cb);
        CTR.assert_eq(ab, cs);
        EXPECT_EQ(ebk.assertion_failed(), ((a + b) != s));
      }
    }
  }
}

TEST(Counter, Fields) {
  test_counter<GF2_128<>>();
  test_counter<Fp128<>>();
}

}  // namespace
}  // namespace proofs
