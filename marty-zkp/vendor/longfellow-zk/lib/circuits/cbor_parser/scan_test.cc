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

#include "circuits/cbor_parser/scan.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <vector>

#include "circuits/logic/counter.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = GF2_128<>;
const Field F;

using EvalBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvalBackend>;
using CounterL = Counter<Logic>;

// random element that fits in a counter
uint64_t random_counter() { return random() % 65535; }

static void one_add(size_t n, const uint64_t A[/*n*/], const uint64_t ds[/*n*/],
                    const bool S[/*n*/]) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const CounterL CTR(L);
  Scan<CounterL> SC(CTR);

  // reference implementation
  std::vector<CounterL::CEltW> BB(n);
  std::vector<Logic::BitW> SS(n);
  std::vector<CounterL::CEltW> AA(n);
  std::vector<CounterL::CEltW> ddss(n);

  for (size_t i = 0; i < n; ++i) {
    AA[i] = CTR.as_counter(A[i]);
    ddss[i] = CTR.as_counter(ds[i]);
    SS[i] = L.bit(S[i]);
  }

  auto s = CTR.as_counter(0);
  for (size_t i = 0; i < n; ++i) {
    if (S[i]) {
      s = AA[i];
    } else {
      s = CTR.add(s, ddss[i]);
    }
    BB[i] = s;
  }

  std::vector<CounterL::CEltW> B(n);
  SC.add(n, B.data(), SS.data(), AA.data(), ddss.data());

  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(B[i].e.elt(), BB[i].e.elt());
  }
}

TEST(Scan, Add) {
  constexpr size_t n = 15;
  uint64_t A[n], ds[n];
  bool S[n];

  for (uint64_t ls = 0; ls < (1 << n); ++ls) {
    for (size_t k = 0; k < n; ++k) {
      S[k] = (ls >> k) & 0x1u;
      A[k] = random_counter();
      ds[k] = random_counter();
    }

    for (size_t n1 = 0; n1 < n; ++n1) {
      one_add(n1, A, ds, S);
    }
  }
}

static void one_add(size_t n, const uint64_t ds[/*n*/]) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const CounterL CTR(L);
  Scan<CounterL> SC(CTR);

  // reference implementation
  std::vector<CounterL::CEltW> BB(n);
  std::vector<CounterL::CEltW> ddss(n);

  for (size_t i = 0; i < n; ++i) {
    ddss[i] = CTR.as_counter(ds[i]);
  }

  auto s = CTR.as_counter(0);
  for (size_t i = 0; i < n; ++i) {
    s = CTR.add(s, ddss[i]);
    BB[i] = s;
  }

  std::vector<CounterL::CEltW> B(n);
  SC.add(n, B.data(), ddss.data());

  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(B[i].e.elt(), BB[i].e.elt());
  }
}

TEST(Scan, UnsegmentedAdd) {
  constexpr size_t n = 100;
  uint64_t ds[n];

  for (size_t k = 0; k < n; ++k) {
    ds[k] = random_counter();
  }

  for (size_t n1 = 0; n1 < n; ++n1) {
    one_add(n1, ds);
  }
}
}  // namespace
}  // namespace proofs
