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

#include "circuits/mdoc/mdoc_examples.h"

#include <stddef.h>

#include <cstdint>
#include <vector>

#include "algebra/fp.h"
#include "circuits/cbor_parser_v2/cbor.h"
#include "circuits/cbor_parser_v2/cbor_testing.h"
#include "circuits/cbor_parser_v2/cbor_witness.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/mdoc/mdoc_zk.h"
#include "gf2k/gf2_128.h"
#include "gtest/gtest.h"

// Make sure we can parse all the mdoc examples.
//
// Kept in circuits/tests/mdoc rather than cbor_parser_v2 so the example-driven
// mdoc tests live in a neutral directory and do not create a cbor_parser_v2 ↔
// mdoc test-layer dependency.
namespace proofs {
namespace {
template <class Field>
void test_examples(const Field& F) {
  using CborWitness = CborWitness<Field>;
  using CborTesting = CborTesting<Field>;

  using EvalBackend = EvaluationBackend<Field>;
  using Logic = Logic<Field, EvalBackend>;
  using CborL = Cbor<Logic>;

  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  const CborL CBOR(L);
  const CborTesting CT(F);
  const CborWitness CW(F);

  for (const MdocTests& test : mdoc_tests) {
    ParsedMdoc pm;
    MdocProverErrorCode ok =
        pm.parse_device_response(test.mdoc_size, test.mdoc);
    EXPECT_TRUE(ok == MDOC_PROVER_SUCCESS);

    size_t n = pm.t_mso_.len - 5;
    const uint8_t* mso = test.mdoc + pm.t_mso_.pos + 5;

    // sanity check
    EXPECT_GT(n, 0);
    EXPECT_EQ(mso[0], 0xa6);

    std::vector<typename CborWitness::v8> inS(n);
    std::vector<typename CborWitness::position_witness> pwS(n);
    CW.compute_witnesses(n, n, mso, inS.data(), pwS.data());

    std::vector<typename CborL::v8> in(n);
    std::vector<typename CborL::position_witness> pw(n);
    CT.convert_witnesses(n, in.data(), pw.data(), inS.data(), pwS.data());

    std::vector<typename CborL::decode> ds(n);
    std::vector<typename CborL::parse_output> ps(n);
    CBOR.decode_and_assert_decode_and_parse(n, ds.data(), ps.data(), in.data(),
                                            pw.data());
  }
}

TEST(MdocExamples, PrimeField) { test_examples(Fp<1>("18446744073709551557")); }

TEST(MdocExamples, BinaryField) { test_examples(GF2_128<>()); }
}  // namespace
}  // namespace proofs