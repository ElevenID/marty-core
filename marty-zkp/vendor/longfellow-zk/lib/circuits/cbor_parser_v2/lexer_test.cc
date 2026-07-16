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

#include <cstdint>
#include <vector>

#include "algebra/fp.h"
#include "circuits/cbor_parser_v2/cbor.h"
#include "circuits/cbor_parser_v2/cbor_testing.h"
#include "circuits/cbor_parser_v2/cbor_witness.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// encoder of input bytes
static inline uint8_t H(uint8_t type, uint8_t count) {
  return (type << 5) | count;
}

uint8_t testcase[] = {
    // Atoms of various size
    H(0, 23),

    H(0, 24),
    33,

    H(0, 25),
    33,
    34,

    H(0, 26),
    33,
    34,
    35,
    36,

    H(0, 27),
    33,
    34,
    35,
    36,
    37,
    38,
    39,
    40,

    // a short string
    H(2, 3),
    'f',
    'o',
    'o',

    // a long string
    H(2, 24),  // header + next byte + string
    /*length of the string*/ 3,
    0xff,
    25,
    31,

    // another small atom
    H(0, 22),

    // a long string
    H(2, 24),  // header + next byte + string
    /*length of the string*/ 4,
    'q',
    'u',
    'u',
    'x',
};

template <class Field>
void test_lexer(const Field& F) {
  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  using Cbor = Cbor<Logic>;
  using CborWitness = CborWitness<Field>;
  const Cbor CBOR(L);
  const CborTesting<Field> CT(F);

  constexpr size_t n = sizeof(testcase) / sizeof(testcase[0]);
  CborWitness CW(F);

  std::vector<typename CborWitness::v8> inS(n);
  std::vector<typename CborWitness::position_witness> pwS(n);
  CW.compute_witnesses(n, n, testcase, inS.data(), pwS.data());

  std::vector<typename Cbor::v8> in(n);
  std::vector<typename Cbor::position_witness> pw(n);
  CT.convert_witnesses(n, in.data(), pw.data(), inS.data(), pwS.data());

  std::vector<typename Cbor::decode> ds(n);
  CBOR.decode_and_assert_decode(n, ds.data(), in.data(), pw.data());
}

TEST(CborLexer, PrimeField) { test_lexer(Fp<1>("18446744073709551557")); }

TEST(CborLexer, BinaryField) { test_lexer(GF2_128<>()); }

}  // namespace
}  // namespace proofs
