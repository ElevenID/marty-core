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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_V2_CBOR_TESTING_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_V2_CBOR_TESTING_H_

#include <stddef.h>

#include "circuits/cbor_parser_v2/cbor.h"
#include "circuits/cbor_parser_v2/cbor_constants.h"
#include "circuits/cbor_parser_v2/cbor_witness.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"

// The purpose of this class is to convert the witnesses from Elt to
// EltW.
//
// Why?
//
// We want EltW in the evaluation backend to be a distinct type from
// Elt.  They are really the same thing, but we want to be able to
// instantiate circuits in the compiler backend as well, and thus
// circuits ought not to rely on the fact that EvaluationBackend::EltW
// is really an Elt in disguise.
// Consequently, tests in the evaluation backend must accept EltW.
//
// The witness generator must produce Elt, otherwise this forces the
// inclusion of Logic in the app.  We don't like that because Logic
// is just a set of helpers to generate circuits, and the final app
// is not supposed to generate circuits (since circuits are part of the
// prover<->verifier API and so they must be set in stone in advance.)
//
// So this class is the price to be paid to maintain this typing
// hygiene.  Time will tell whether it was worth it.

namespace proofs {

template <class Field>
class CborTesting {
  using EvalBackend = EvaluationBackend<Field>;
  using LogicF = Logic<Field, EvalBackend>;
  using EltW = typename LogicF::EltW;
  using BitW = typename LogicF::BitW;
  using CborL = Cbor<LogicF>;
  using CborWitnessF = CborWitness<Field>;

 public:
  explicit CborTesting(const Field& F) : f_(F) {}

  void convert_witnesses(
      size_t n, typename CborL::v8 in[/*n*/],
      typename CborL::position_witness pw[/*n*/],
      const typename CborWitnessF::v8 inS[/*n*/],
      const typename CborWitnessF::position_witness pwS[/*n*/]) const {
    const EvalBackend ebk(f_);
    const LogicF L(&ebk, f_);
    const Counter<LogicF> CTR(L);

    for (size_t i = 0; i < n; ++i) {
      for (size_t j = 0; j < 8; ++j) {
        in[i][j] = BitW(L.konst(inS[i][j]), f_);
      }
      pw[i].encoded_header = L.konst(pwS[i].encoded_header);
      pw[i].encoded_sel = L.konst(pwS[i].encoded_sel);
      pw[i].slen_next = CTR.as_counter(pwS[i].slen_next);
      for (size_t j = 0; j < CborWitnessF::kNCounters; ++j) {
        pw[i].cc_next[j] = CTR.as_counter(pwS[i].cc_next[j]);
      }
      pw[i].invprod_decode = L.konst(pwS[i].invprod_decode);
      pw[i].invprod_parse = L.konst(pwS[i].invprod_parse);
    }
  }

  // Return an index that can be fed to a circuit in the
  // evaluation backend (i.e., a bit vector).
  typename CborL::vindex index(size_t j) const {
    const EvalBackend ebk(f_);
    const LogicF L(&ebk, f_);
    return L.template vbit<CborConstants::kIndexBits>(j);
  }

 private:
  const Field& f_;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_V2_CBOR_TESTING_H_
