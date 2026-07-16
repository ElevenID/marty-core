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

#include "circuits/logic/bit_plucker.h"

#include <stddef.h>

#include "algebra/fp.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_constants.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <size_t LOGN, class Field>
void test_plucker(const Field& F) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;

  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  constexpr size_t N = 1 << LOGN;
  const BitPluckerEncoder<Field, LOGN> PE(F);
  const BitPlucker<Logic, LOGN> P(L);

  for (size_t i = 0; i < N; ++i) {
    auto enc = PE.encode(i);
    auto got = P.pluck(L.konst(enc));
    for (size_t k = 0; k < LOGN; ++k) {
      EXPECT_EQ(L.eval(got[k]), L.konst((i >> k) & 1));
    }
  }
}

TEST(BitPlucker, PluckPrimeField) {
  const Fp<1> F("18446744073709551557");
  test_plucker<1>(F);
  test_plucker<2>(F);
  test_plucker<3>(F);
  test_plucker<4>(F);
  test_plucker<5>(F);
}

TEST(BitPlucker, PluckBinaryField) {
  const GF2_128<> F;
  test_plucker<1>(F);
  test_plucker<2>(F);
  test_plucker<3>(F);
  test_plucker<4>(F);
  test_plucker<5>(F);
}

template <size_t LOGN, class Field>
void pluck_size(const char *name, const Field &F) {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;

  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  const BitPlucker<LogicCircuit, LOGN> PC(LC);

  auto eC = LC.eltw_input();
  auto r = PC.pluck(eC);
  for (size_t k = 0; k < LOGN; ++k) {
    LC.output(r[k], k);
  }
  auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
  dump_info(name, LOGN, Q);
}

TEST(BitPlucker, PluckSizePrimeField) {
  using Field = Fp<1>;
  const Field F("18446744073709551557");
  const char *name = "pluck<FP<1>>";
  pluck_size<1>(name, F);
  pluck_size<2>(name, F);
  pluck_size<3>(name, F);
  pluck_size<4>(name, F);
  pluck_size<5>(name, F);
  pluck_size<6>(name, F);
  pluck_size<7>(name, F);
  pluck_size<8>(name, F);
}

TEST(BitPlucker, PluckSizeBinaryField) {
  using Field = GF2_128<>;
  const Field F;
  const char *name = "pluck<GF2_128<>>";
  pluck_size<1>(name, F);
  pluck_size<2>(name, F);
  pluck_size<3>(name, F);
  pluck_size<4>(name, F);
  pluck_size<5>(name, F);
  pluck_size<6>(name, F);
  pluck_size<7>(name, F);
  pluck_size<8>(name, F);
}

TEST(BitPlucker, EltMuxer) {
  using Field = Fp<1>;
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using EltW = Logic::EltW;

  const Field F("257");
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const EltW zero = L.konst(0);
  const EltW one = L.konst(1);

  EltW arr_z[] = {zero, one, one, one, one, one, one, one};
  EltW arr_e[] = {zero, one, zero, one, zero, one, zero, one};
  EltW arr_r[] = {zero, zero, one, one, zero, zero, one, one};
  EltW arr_s[] = {zero, zero, zero, zero, one, one, one, one};

  const EltMuxer<Logic, 8> em_z(L, arr_z);
  const EltMuxer<Logic, 8> em_e(L, arr_e);
  const EltMuxer<Logic, 8> em_r(L, arr_r);
  const EltMuxer<Logic, 8> em_s(L, arr_s);

  for (size_t i = 0; i < 8; ++i) {
    auto enc = bit_plucker_point<Field, 8>()(i, F);

    L.assert_eq(em_z.mux(L.konst(enc)), arr_z[i]);
    L.assert_eq(em_e.mux(L.konst(enc)), arr_e[i]);
    L.assert_eq(em_r.mux(L.konst(enc)), arr_r[i]);
    L.assert_eq(em_s.mux(L.konst(enc)), arr_s[i]);
  }
}

// Test use of the EltMuxer machinery to test whether a smaller muxer input
// is in range. In this case, we want to test whether the muxed input is in
// {0,1,2,3,4,5,6,7}. We want to ensure that there are no false positives and
// thus the test iterates over the entire field.
TEST(BitPlucker, EltMuxer9) {
  using Field = Fp<1>;
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using EltW = Logic::EltW;

  const Field F("257");
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const EltW zero = L.konst(0);
  const EltW one = L.konst(1);

  EltW arr_v[] = {zero, zero, zero, zero, zero, zero, zero, zero, one};
  const EltMuxer<Logic, 9, 8> em2(L, arr_v);
  for (size_t i = 0; i < 128 + /*intentional extra element*/ 1; ++i) {
    auto enc = bit_plucker_point<Field, 8>()(i, F);
    if (i < 9) {
      L.assert_eq(em2.mux(L.konst(enc)), arr_v[i]);
    } else {
      EXPECT_NE(em2.mux(L.konst(enc)).elt(), F.zero());
    }
  }
}

}  // namespace
}  // namespace proofs
