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

#include <stddef.h>

#include <vector>

#include "algebra/fp.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/logic/unary.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void one_size(const Field& F, const char* name, bool eq_or_lt) {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using BitWC = LogicCircuit::BitW;
  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  const Unary<LogicCircuit> U(LC);

  constexpr size_t W = 12;
  using BV = typename LogicCircuit::template bitvec<W>;
  size_t n = 1u << W;
  std::vector<BitWC> A(n);

  BV jj = LC.template vinput<W>();
  if (eq_or_lt) {
    U.eq(n, A.data(), jj);
  } else {
    U.lt(n, A.data(), jj);
  }
  for (size_t i = 0; i < n; ++i) {
    LC.output(A[i], i);
  }
  auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
  dump_info("foo", n, Q);
}

TEST(UnarySize, PrimeField) {
  one_size(Fp<1>("18446744073709551557"), "eq_fp", /*eq_or_lt=*/true);
  one_size(Fp<1>("18446744073709551557"), "lt_fp", /*eq_or_lt=*/false);
}
TEST(UnarySize, BinaryField) {
  one_size(GF2_128<>(), "eq_gf", /*eq_or_lt=*/true);
  one_size(GF2_128<>(), "lt_gf", /*eq_or_lt=*/false);
}

}  // namespace
}  // namespace proofs
