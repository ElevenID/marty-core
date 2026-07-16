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
#include "circuits/cbor_parser_v2/cbor.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

template <class Field>
void parser_size(const char* name, const Field& F) {
  using CompilerBackend = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackend>;
  using CborC = Cbor<LogicCircuit>;

  set_log_level(INFO);

  size_t sizes[] = {247, 503, 1079, 1591, 2231, 2551};

  for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i) {
    size_t n = sizes[i];
    QuadCircuit<Field> Q(F);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, F);
    const CborC CBORC(LC);
    const Counter<LogicCircuit> CTRC(LC);

    std::vector<typename CborC::v8> inC(n);
    std::vector<typename CborC::position_witness> pwC(n);

    // input
    for (size_t j = 0; j < n; ++j) {
      inC[j] = LC.template vinput<8>();
    }

    // witnesses
    CBORC.witness_wires(n, pwC.data());

    std::vector<typename CborC::decode> dsC(n);
    std::vector<typename CborC::parse_output> psC(n);
    CBORC.decode_and_assert_decode_and_parse(n, dsC.data(), psC.data(),
                                             inC.data(), pwC.data());

    auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
    dump_info<Field>(name, n, Q);
  }
}

TEST(CborParseSize, DecodeAndAssertDecodeAndParse_PrimeField) {
  parser_size("Fp<1>", Fp<1>("18446744073709551557"));
}
TEST(CborParseSize, DecodeAndAssertDecodeAndParse_BinaryField) {
  parser_size("GF2_128<>", GF2_128<>());
}
}  // namespace
}  // namespace proofs
