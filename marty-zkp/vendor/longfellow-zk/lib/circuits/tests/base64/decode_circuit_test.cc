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
#include <cstring>
#include <memory>
#include <string>

#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/base64/decode.h"
#include "gf2k/gf2_128.h"
#include "sumcheck/prover.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

typedef GF2_128<> Field;
const Field F;

using CompilerBackend = CompilerBackend<Field>;
using LogicCircuit = Logic<Field, CompilerBackend>;

using EvaluationBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvaluationBackend>;

TEST(Base64, Circuit) {
  QuadCircuit<Field> Q(F);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, F);
  const EvaluationBackend ebk(F);
  const Logic L(&ebk, F);
  constexpr size_t nc = 1;

  using v8 = LogicCircuit::v8;
  using v6 = LogicCircuit::template bitvec<6>;

  Base64Decoder<LogicCircuit> bd(LC);

  v8 in = LC.vinput<8>();
  v6 out;

  bd.decode(in, out);
  LC.voutput(out, 0);

  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info<Field>("Base64Decoder", nc, Q);

  // now evaluate the circuit on all inputs
  std::string valid =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

  // Loop over all input symbols.
  for (size_t c = 0; c < 256; ++c) {
    auto win = L.template vbit<8>(c);
    auto W = std::make_unique<Dense<Field>>(nc, /*constant one*/ 1 + 8);
    W->v_[0] = F.one();
    for (size_t i = 0; i < 8; ++i) {
      W->v_[1 + i] = L.eval(win[i]).elt();
    }

    Prover<Field>::inputs pin;
    Prover<Field> prover(F);
    auto V = prover.eval_circuit(&pin, CIRCUIT.get(), W->clone(), F);

    size_t ind = valid.find(c);
    if (ind != std::string::npos) {
      auto want = L.template vbit<6>(ind);
      for (size_t i = 0; i < 6; ++i) {
        EXPECT_EQ(V->v_[i], L.eval(want[i]).elt());
      }
    } else {
      EXPECT_EQ(V, nullptr);
    }
  }
}

}  // namespace
}  // namespace proofs
