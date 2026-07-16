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

#ifndef PRIVACY_PROOFS_ZK_LIB_SUMCHECK_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_SUMCHECK_VERIFIER_H_

#include <stddef.h>

#include <memory>

#include "arrays/dense.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "sumcheck/transcript_sumcheck.h"
#include "sumcheck/verifier_layers.h"

namespace proofs {
// Full sumcheck verifier that verifies the layers
// via verifier_layers<> and then checks the input
// binding directly.
template <class Field>
class Verifier : public VerifierLayers<Field> {
  using super = VerifierLayers<Field>;
  using typename super::claims;
  using typename super::Elt;

 public:
  static bool verify(const char** why, const Circuit<Field>* circ,
                      const Proof<Field>* proof,
                      std::unique_ptr<Dense<Field>> V,
                      std::unique_ptr<Dense<Field>> X, Transcript& ts,
                      const Field& F) {
    if (why == nullptr || circ == nullptr || proof == nullptr ||
        V == nullptr || X == nullptr) {
      return false;
    }

    claims cl{};
    Challenge<Field> ch(circ->nl);
    TranscriptSumcheck<Field> tss(ts, F);
    tss.write_input(X.get());

    if (!(super::circuit(why, &cl, circ, proof, &ch, std::move(V), tss,
                         F))) {
      return false;
    }

    // Final check on W, the input wires.
    // bind the copy variables:
    X->bind_all(circ->logc, cl.q, F);
    X->reshape(cl.nv);

    // bind the gate variables, for two hands:
    auto X1 = X->clone();
    Dense<Field>* VH[2] = {X.get(), X1.get()};

    for (size_t hand = 0; hand < 2; ++hand) {
      VH[hand]->bind_all(cl.logv, cl.g[hand], F);
      Elt got = VH[hand]->scalar();
      if (got != cl.claim[hand]) {
        *why = "got != cl.claim[hand]";
        return false;
      }
    }

    return true;
  }

  Verifier() = delete;
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_SUMCHECK_VERIFIER_H_
