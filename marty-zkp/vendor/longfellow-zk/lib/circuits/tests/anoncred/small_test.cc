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

#include "circuits/tests/anoncred/small.h"

#include <stdint.h>

#include <cstddef>
#include <memory>
#include <vector>

#include "algebra/convolution.h"
#include "algebra/fp2.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/anoncred/small_examples.h"
#include "circuits/tests/anoncred/small_io.h"
#include "circuits/tests/anoncred/small_witness.h"
#include "ec/p256.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Sw = SmallWitness<P256, Fp256Base, Fp256Scalar>;
static constexpr size_t kNumAttr = 1;

// Helper functions to create circuit and fill the witness.
std::unique_ptr<Circuit<Fp256Base>> make_circuit() {
  using CompilerBackend = CompilerBackend<Fp256Base>;
  using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
  using v8 = typename LogicCircuit::v8;
  using EltW = LogicCircuit::EltW;
  using Small = Small<LogicCircuit, Fp256Base, P256, kNumAttr>;
  QuadCircuit<Fp256Base> Q(p256_base);
  const CompilerBackend cbk(&Q);
  const LogicCircuit LC(&cbk, p256_base);
  Small small(LC, p256, n256_order);

  EltW pkX = LC.eltw_input(), pkY = LC.eltw_input(), htr = LC.eltw_input();
  typename Small::OpenedAttribute oa[kNumAttr];
  for (size_t ai = 0; ai < kNumAttr; ++ai) {
    oa[ai].input(LC);
  }

  v8 now[kDateLen];
  for (size_t i = 0; i < kDateLen; ++i) {
    now[i] = LC.template vinput<8>();
  }

  Q.private_input();

  Small::Witness vwc;
  vwc.input(LC);

  small.assert_credential(pkX, pkY, htr, oa, now, vwc);

  auto CIRCUIT = Q.mkcircuit(/*nc=*/1);
  dump_info("mdocsmall", Q);
  return CIRCUIT;
}

void fill_witness(Dense<Fp256Base> &W, Dense<Fp256Base> &pub) {
  using Elt = Fp256Base::Elt;
  Elt pkX, pkY;

  // Generate a witness from the mdoc data structure to remain close
  // to the application use case.
  Sw sw(p256, p256_scalar);
  SmallOpenedAttribute age = {74, 1, (uint8_t *)"\xf5", 1};
  std::vector<SmallOpenedAttribute> show(kNumAttr, age);

  {
    constexpr size_t t_ind = 0;
    const SmallTest &test = mdoc_small_tests[t_ind];
    pkX = p256_base.of_string(test.pkx);
    pkY = p256_base.of_string(test.pky);
    bool ok =
        sw.compute_witness(pkX, pkY, test.mdoc, test.mdoc_size, test.transcript,
                           test.transcript_size, test.now, test.sigr, test.sigs,
                           test.sigtr, test.sigts);

    check(ok, "Could not compute signature witness");
    log(INFO, "Witness done");
  }

  {
    DenseFiller<Fp256Base> filler(W);
    DenseFiller<Fp256Base> pub_filler(pub);
    filler.push_back(p256_base.one());
    pub_filler.push_back(p256_base.one());
    filler.push_back(pkX);
    pub_filler.push_back(pkX);
    filler.push_back(pkY);
    pub_filler.push_back(pkY);
    filler.push_back(sw.e2_);
    pub_filler.push_back(sw.e2_);

    for (size_t ai = 0; ai < kNumAttr; ++ai) {
      filler.push_back(show[ai].ind_, 8, p256_base);
      pub_filler.push_back(show[ai].ind_, 8, p256_base);

      filler.push_back(show[ai].len_, 8, p256_base);
      pub_filler.push_back(show[ai].len_, 8, p256_base);

      for (size_t i = 0; i < 32; ++i) {
        uint8_t v = show[ai].value_.size() > i ? show[ai].value_[i] : 0;
        filler.push_back(v, 8, p256_base);
        pub_filler.push_back(v, 8, p256_base);
      }
    }

    for (size_t i = 0; i < kDateLen; ++i) {
      filler.push_back(sw.now_[i], 8, p256_base);
      pub_filler.push_back(sw.now_[i], 8, p256_base);
    }

    sw.fill_witness(filler, true);
    log(INFO, "Fill done");
  }
}

// ============ Tests ==========================================================

TEST(mdoc, mdoc_small_test) {
  set_log_level(INFO);

  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT = make_circuit();

  // ========= Fill witness
  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);
  fill_witness(W, pub);

  // =========== ZK test
  run2_test_zk(
      *CIRCUIT, W, pub, p256_base,
      p256_base.of_string("1126492241464102818735004576096902583730188404304894"
                          "08729223714171582664680802"), /* omega_x*/
      p256_base.of_string("8408799435854090769574046142781866056018216899718237"
                          "8749313018254450460212908"), /* omega_y */
      1ull << 31);
}

// ============ Benchmarks =====================================================
void BM_AnonCred(benchmark::State &state) {
  std::unique_ptr<Circuit<Fp256Base>> CIRCUIT = make_circuit();

  auto W = Dense<Fp256Base>(1, CIRCUIT->ninputs);
  auto pub = Dense<Fp256Base>(1, CIRCUIT->npub_in);

  fill_witness(W, pub);

  using f2_p256 = Fp2<Fp256Base>;
  using Elt2 = f2_p256::Elt;
  using FftExtConvolutionFactory = FFTExtConvolutionFactory<Fp256Base, f2_p256>;
  using RSFactory = ReedSolomonFactory<Fp256Base, FftExtConvolutionFactory>;

  // Root of unity for the f_p256^2 extension field.
  static constexpr char kRootX[] =
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802";
  static constexpr char kRootY[] =
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908";

  const f2_p256 p256_2(p256_base);
  const Elt2 omega = p256_2.of_string(kRootX, kRootY);
  const FftExtConvolutionFactory fft_b(p256_base, p256_2, omega, 1ull << 31);
  const RSFactory rsf(fft_b, p256_base);

  Transcript tp((uint8_t *)"test", 4);
  SecureRandomEngine rng;

  for (auto s : state) {
    ZkProof<Fp256Base> zkpr(*CIRCUIT, 4, 128);
    ZkProver<Fp256Base, RSFactory> prover(*CIRCUIT, p256_base, rsf);
    prover.commit(zkpr, W, tp, rng);
    prover.prove(zkpr, W, tp);
  }
}
BENCHMARK(BM_AnonCred);

}  // namespace
}  // namespace proofs
