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

#include "circuits/mac/mac_circuit.h"

#include <stddef.h>
#include <string.h>

#include <cstdint>
#include <memory>
#include <utility>

#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/mac/mac_reference.h"
#include "circuits/mac/mac_witness.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "random/secure_random_engine.h"
#include "sumcheck/circuit.h"
#include "sumcheck/testing.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

// This test subsumes the evaluation test.
TEST(MAC, full_circuit_test_128) {
  set_log_level(INFO);
  constexpr size_t kNum = 3;

  size_t ninput;
  std::unique_ptr<Circuit<Fp256Base>> circuit;

  /*scope to delimit compile-time*/ {
    using CompilerBackend = CompilerBackend<Fp256Base>;
    using LogicCircuit = Logic<Fp256Base, CompilerBackend>;
    using v128 = LogicCircuit::v128;
    QuadCircuit<Fp256Base> Q(p256_base);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, p256_base);
    using MACCircuit =
        MAC<LogicCircuit, BitPlucker<LogicCircuit, kMACPluckerBits>>;
    MACCircuit mac(LC);

    MACCircuit::Witness vwc[kNum];
    LogicCircuit::EltW msg[kNum];
    v128 mv[kNum][2];
    v128 a_v[kNum];
    for (size_t i = 0; i < kNum; ++i) {
      msg[i] = LC.eltw_input();
      mv[i][0] = LC.vinput<128>();
      mv[i][1] = LC.vinput<128>();
      a_v[i] = LC.vinput<128>();
    }

    Q.private_input();
    for (size_t i = 0; i < kNum; ++i) {
      vwc[i].input(LC);
    }
    for (size_t i = 0; i < kNum; ++i) {
      mac.verify_mac(msg[i], mv[i], a_v[i], vwc[i], n256_order);
    }

    circuit = Q.mkcircuit(1);
    dump_info("mac verify p256", Q);
    ninput = Q.ninput();
  }

  log(INFO, "Compile done");
  /*------------------------------------------------------------*/
  // Witness-creation time + fill inputs
  using gf2k = GF2_128<>::Elt;
  GF2_128<> gf;
  MACReference<GF2_128<>> mac_ref;
  SecureRandomEngine rng;

  uint8_t test_msg[32];

  for (size_t t = 0; t < 10; ++t) {
    rng.bytes(test_msg, 32);

    auto W = std::make_unique<Dense<Fp256Base>>(1, ninput);
    DenseFiller<Fp256Base> filler(*W);
    filler.push_back(p256_base.one());

    Fp256Base::Elt msg_elt = p256_base.of_bytes_field(test_msg).value();

    gf2k av, ap[2], mac[2];
    mac_ref.sample(&av, 1, &rng);
    mac_ref.sample(ap, 2, &rng);
    mac_ref.compute(mac, av, ap, test_msg);

    MacWitness<Fp256Base> vw(p256_base, gf);
    vw.compute_witness(ap, test_msg);

    for (size_t i = 0; i < kNum; ++i) {
      filler.push_back(msg_elt);

      // Fill inputs
      for (size_t j = 0; j < 2; ++j) {
        fill_gf2k<GF2_128<>, Fp256Base>(mac[j], filler, p256_base);
      }
      fill_gf2k<GF2_128<>, Fp256Base>(av, filler, p256_base);
    }

    for (size_t i = 0; i < kNum; ++i) {
      vw.fill_witness(filler);
    }

    log(INFO, "Fill done");
    /*------------------------------------------------------------*/
    // Prove
    Proof<Fp256Base> proof(circuit->nl);
    run_prover<Fp256Base>(circuit.get(), W->clone(), &proof, p256_base);

    log(INFO, "Prover done");
    /*------------------------------------------------------------*/
    // Verify
    run_verifier<Fp256Base>(circuit.get(), std::move(W), proof, p256_base);
    log(INFO, "Verify done");
  }
}

TEST(MAC, full_circuit_GF2_128) {
  set_log_level(INFO);
  using f_128 = GF2_128<>;
  size_t ninput;
  std::unique_ptr<Circuit<f_128>> circuit;
  f_128 F;

  /*scope to delimit compile-time*/ {
    using CompilerBackend = CompilerBackend<f_128>;
    using LogicCircuit = Logic<f_128, CompilerBackend>;
    using EltW = LogicCircuit::EltW;
    using v256 = LogicCircuit::v256;
    QuadCircuit<f_128> Q(F);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, F);
    using MACCircuit =
        MACGF2<CompilerBackend, BitPlucker<LogicCircuit, kMACPluckerBits>>;
    MACCircuit mac(LC);
    MACCircuit::Witness vwc;

    v256 msg = LC.vinput<256>();
    EltW mv[2] = {LC.eltw_input(), LC.eltw_input()};
    EltW a_v = LC.eltw_input();
    Q.private_input();
    vwc.input(LC);
    mac.verify_mac(mv, a_v, msg, vwc);

    circuit = Q.mkcircuit(1);
    dump_info("mac_gf2_128 verify", Q);
    ninput = Q.ninput();
  }

  log(INFO, "Compile done");
  /*------------------------------------------------------------*/
  // Witness-creation time + fill inputs
  using gf2k = f_128::Elt;
  MACReference<f_128> mac_ref;
  SecureRandomEngine rng;

  uint8_t test_msg[32];

  for (size_t t = 0; t < 10; ++t) {
    rng.bytes(test_msg, 32);

    auto W = std::make_unique<Dense<f_128>>(1, ninput);
    DenseFiller<f_128> filler(*W);
    filler.push_back(F.one());

    for (size_t i = 0; i < 256; ++i) {
      filler.push_back((test_msg[i / 8] >> (i % 8) & 0x1) ? F.one() : F.zero());
    }

    gf2k av, ap[2], mac[2];
    mac_ref.sample(&av, 1, &rng);
    mac_ref.sample(ap, 2, &rng);
    mac_ref.compute(mac, av, ap, test_msg);

    MacGF2Witness vw;
    vw.compute_witness(ap);

    // Fill inputs
    for (size_t i = 0; i < 2; ++i) {
      filler.push_back(mac[i]);
    }
    filler.push_back(av);
    vw.fill_witness(filler);

    log(INFO, "Fill done");
    /*------------------------------------------------------------*/
    // Prove
    Proof<f_128> proof(circuit->nl);
    run_prover<f_128>(circuit.get(), W->clone(), &proof, F);

    log(INFO, "Prover done");
    /*------------------------------------------------------------*/
    // Verify
    run_verifier<f_128>(circuit.get(), std::move(W), proof, F);
    log(INFO, "Verify done");
  }
}

}  // namespace
}  // namespace proofs
