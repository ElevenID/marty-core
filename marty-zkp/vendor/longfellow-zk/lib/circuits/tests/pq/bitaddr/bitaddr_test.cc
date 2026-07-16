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

#include "circuits/tests/pq/bitaddr/bitaddr.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/bitaddr/bitaddr_witness.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_testing.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {

using Field = Fp256k1Base;
using EC = P256k1;
using CompilerBackendType = CompilerBackend<Field>;
using LogicType = Logic<Field, CompilerBackendType>;
using EltW = typename LogicType::EltW;
using CircuitType = BitaddrCircuit<LogicType>;
using WitnessHelper = BitaddrWitness;

struct BitaddrTestCase {
  const char* secret_key_hex;
  const char* address_hex;
};

const BitaddrTestCase kBitaddrTestCases[] = {
    {"0x9FE33A7A06BD0FE6F5208A61991C49B5B4DD12DC42D9903E789F5118F9675030",
     "0xE30798BD7D0193D12F3F6FEA6D9FF6FEAA2AC721"},
    {"0x8c6d70fb57790757d9047916962f90a16823ca87803a3915152865768565251d",
     "0x229c2b46a1cc631f0733b4baf6037ff2cbdf39c1"},
    {"0x73a6e34a2a5d783bed323a9d241945ed3e7038f1923aad669e651405ad44192f",
     "0x94eff2102af4714cc85ed9059936994ace60c114"},
    {"0x4a48b0d30c0e4df943f799c115164d1790a29cfb938b8089fcca353f97c75785",
     "0x18c0a6ec42aaa4e2041d27bb1c832c8bf264127d"},
    {"0x9554dca942a256e6baddeaf55e9877a60d5b0af1175a0b619f1a95b7f4a3e3e2",
     "0xcb74d73967375d038117292d33e36e7812a37c89"},
    {"0x919bae1e9ab4ad1df400cf21a2939acc3bc2214d30a437c4f0542f9f16bdb05e",
     "0x58e0b8a4f94ac1ba44f1b7598c3ef024c7956670"},
    {"0x40c43276d55b76153c82c8a37521ebed2c0a6b2ab0733362254b94b6299598c4",
     "0x204e544155507a4ee3ca7a2c8e13669e52b2b999"},
};

std::unique_ptr<Circuit<Field>> make_circuit() {
  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackendType cbk(&Q);
  const LogicType lc(&cbk, p256k1_base);
  CircuitType circuit(lc);

  EltW addr = lc.eltw_input();

  Q.private_input();
  typename CircuitType::Witness w;
  w.input(lc);

  circuit.assert_bitaddr(addr, w);
  return Q.mkcircuit(1);
}

// Uses a fixed basis of primes to compute a convolution for 64--521 bit values.
// The CRT class must use the same Field in its definition.
template <class Field, class CRT>
void run_test_zk(const Circuit<Field>& circuit, Dense<Field>& W,
                 const Dense<Field>& pub, const Field& base) {
  // Build the relevant algebra objects.
  using CrtConvolutionFactory = CrtConvolutionFactory<CRT, Field>;
  using RSFactory = ReedSolomonFactory<Field, CrtConvolutionFactory>;

  const CrtConvolutionFactory fft(base);
  const RSFactory rsf(fft, base);

  ZkProof<Field> zkpr(circuit, kLigeroRate, kLigeroNreq);

  Transcript tp((uint8_t*)"zk_test", 7, kVersion);
  SecureRandomEngine rng;
  ZkProver<Field, RSFactory> prover(circuit, base, rsf);
  prover.commit(zkpr, W, tp, rng);
  EXPECT_TRUE(prover.prove(zkpr, W, tp));

  // ======= run verifier =============
  // Re-parse the proof to simulate a different client.
  std::vector<uint8_t> zbuf;
  zkpr.write(zbuf, base);
  ZkProof<Field> zkpv(circuit, kLigeroRate, kLigeroNreq);
  ReadBuffer rb(zbuf);
  EXPECT_TRUE(zkpv.read(rb, base));

  ZkVerifier<Field, RSFactory> verifier(circuit, rsf, kLigeroRate, kLigeroNreq,
                                        base);
  Transcript tv((uint8_t*)"zk_test", 7, kVersion);
  verifier.recv_commitment(zkpv, tv);
  EXPECT_TRUE(verifier.verify(zkpv, pub, tv));
}

void fill_input(Dense<Field>& W, bool prover,
                const BitaddrTestCase& test_case) {
  DenseFiller<Field> filler(W);
  filler.push_back(p256k1_base.one());

  auto sk_opt = Field::N::of_untrusted_string(test_case.secret_key_hex);
  EXPECT_TRUE(sk_opt.has_value());
  typename Field::N sk = *sk_opt;

  auto addr_opt = Field::N::of_untrusted_string(test_case.address_hex);
  EXPECT_TRUE(addr_opt.has_value());
  typename Field::N addr_n = *addr_opt;

  filler.push_back(p256k1_base.of_scalar_field(addr_n));

  if (prover) {
    WitnessHelper w(p256k1_base);
    EXPECT_TRUE(w.compute_witness(sk));
    w.fill_witness(filler);
  }
}

TEST(BitaddrTest, ZkProverVerifier) {
  auto CIRCUIT = make_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_input(*W, true, kBitaddrTestCases[0]);

  auto pub = std::make_unique<Dense<Field>>(1, CIRCUIT->npub_in);
  fill_input(*pub, false, kBitaddrTestCases[0]);

  run_test_zk<Field, CRT256<Field>>(*CIRCUIT, *W, *pub, p256k1_base);
}

TEST(BitaddrTest, CircuitSize) {
  QuadCircuit<Field> Q(p256k1_base);
  const CompilerBackendType cbk(&Q);
  const LogicType lc(&cbk, p256k1_base);
  CircuitType circuit(lc);

  EltW addr = lc.eltw_input();

  Q.private_input();
  typename CircuitType::Witness w;
  w.input(lc);

  circuit.assert_bitaddr(addr, w);
  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("bitaddr", Q);
}

TEST(BitaddrTest, LogicEvaluation) {
  // 1. Setup Backend
  using EvalBackend = EvaluationBackend<Field>;
  using LogicEval = Logic<Field, EvalBackend>;
  using CircuitEval = BitaddrCircuit<LogicEval>;
  using WitnessEval = typename CircuitEval::Witness;

  // Use true (default) to crash on assertion failure and get stack trace
  EvalBackend ebk(p256k1_base);
  LogicEval lc(&ebk, p256k1_base);
  CircuitEval circuit(lc);
  BitPluckerEncoder<Field, 2> enc(p256k1_base);

  // 2. Generate Witness Values
  for (const auto& test_case : kBitaddrTestCases) {
    auto sk_opt = Field::N::of_untrusted_string(test_case.secret_key_hex);
    check(sk_opt.has_value(), "failed to parse sk");
    typename Field::N sk = *sk_opt;

    auto addr_opt = Field::N::of_untrusted_string(test_case.address_hex);
    check(addr_opt.has_value(), "failed to parse addr");
    typename Field::N addr_n = *addr_opt;

    // Fill witness
    using WitnessHelper = BitaddrWitness;
    WitnessHelper witness(p256k1_base);
    ASSERT_TRUE(witness.compute_witness(sk));

    // Because this is eval, convert the witness to logic witness manually.
    WitnessEval cw;
    for (size_t i = 0; i < EC::kBits; ++i) {
      cw.ecpk.bits[i] = lc.konst(witness.ecpk_.bits_[i]);
      if (i < EC::kBits - 1) {
        cw.ecpk.int_x[i] = lc.konst(witness.ecpk_.int_x_[i]);
        cw.ecpk.int_y[i] = lc.konst(witness.ecpk_.int_y_[i]);
        cw.ecpk.int_z[i] = lc.konst(witness.ecpk_.int_z_[i]);
      }
    }

    cw.pk_x = lc.konst(witness.pkx_);
    cw.pk_y = lc.konst(witness.pky_);

    auto nx = p256k1_base.from_montgomery(witness.pkx_);
    auto ny = p256k1_base.from_montgomery(witness.pky_);

    for (size_t i = 0; i < EC::kBits; ++i) {
      cw.pk_x_bits[i] = LogicEval::BitW(
          lc.konst(p256k1_base.of_scalar(nx.bit(i))), p256k1_base);
      cw.pk_y_bits[i] = LogicEval::BitW(
          lc.konst(p256k1_base.of_scalar(ny.bit(i))), p256k1_base);
    }

    auto to_packed = [&](uint32_t val) {
      auto packed_arr = enc.mkpacked_v32(val);
      typename LogicEval::EltW packed[16];
      for (size_t k = 0; k < 16; ++k) {
        packed[k] = lc.konst(packed_arr[k]);
      }
      return std::to_array(packed);
    };

    for (int k = 0; k < 48; ++k)
      cw.sha.outw[k] = to_packed(witness.sha_.outw[k]);
    for (int k = 0; k < 64; ++k)
      cw.sha.oute[k] = to_packed(witness.sha_.oute[k]);
    for (int k = 0; k < 64; ++k)
      cw.sha.outa[k] = to_packed(witness.sha_.outa[k]);
    for (int k = 0; k < 8; ++k) cw.sha.h1[k] = to_packed(witness.sha_.h1[k]);

    for (int k = 0; k < 80; ++k)
      cw.ripemd.left_temp[k] = to_packed(witness.ripemd_.left_temp[k]);
    for (int k = 0; k < 80; ++k)
      cw.ripemd.left_calc[k] = to_packed(witness.ripemd_.left_calc[k]);
    for (int k = 0; k < 80; ++k)
      cw.ripemd.right_temp[k] = to_packed(witness.ripemd_.right_temp[k]);
    for (int k = 0; k < 80; ++k)
      cw.ripemd.right_calc[k] = to_packed(witness.ripemd_.right_calc[k]);
    for (int k = 0; k < 5; ++k)
      cw.ripemd.h_out[k] = to_packed(witness.ripemd_.h_out[k]);

    typename EvalBackend::V addr_v(p256k1_base.of_scalar_field(addr_n));
    circuit.assert_bitaddr(addr_v, cw);

    EXPECT_FALSE(ebk.assertion_failed());
  }
}

// ===================== Benchmarks ==============================

void BM_BitaddrProver(benchmark::State& state) {
  set_log_level(LogLevel::ERROR);
  auto CIRCUIT = make_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_input(*W, true, kBitaddrTestCases[0]);

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  const ConvolutionFactory fft(p256k1_base);
  const RSFactory rsf(fft, p256k1_base);

  Transcript tp((uint8_t*)"bench_prover", 12, kVersion);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, p256k1_base, rsf);

  for (auto s : state) {
    prover.commit(zkpr, *W, tp, rng);
    EXPECT_TRUE(prover.prove(zkpr, *W, tp));
  }
}
BENCHMARK(BM_BitaddrProver);

void BM_BitaddrVerifier(benchmark::State& state) {
  set_log_level(LogLevel::ERROR);
  auto CIRCUIT = make_circuit();
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_input(*W, true, kBitaddrTestCases[0]);

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  const ConvolutionFactory fft(p256k1_base);
  const RSFactory rsf(fft, p256k1_base);

  Transcript tp((uint8_t*)"bench_verifier", 14, kVersion);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kLigeroRate, kLigeroNreq);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, p256k1_base, rsf);
  prover.commit(zkpr, *W, tp, rng);
  EXPECT_TRUE(prover.prove(zkpr, *W, tp));

  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kLigeroRate, kLigeroNreq,
                                        p256k1_base);
  auto pub = std::make_unique<Dense<Field>>(1, CIRCUIT->npub_in);
  fill_input(*pub, false, kBitaddrTestCases[0]);

  for (auto s : state) {
    Transcript tv((uint8_t*)"bench_verifier", 14, kVersion);
    verifier.recv_commitment(zkpr, tv);
    EXPECT_TRUE(verifier.verify(zkpr, *pub, tv));
  }
}
BENCHMARK(BM_BitaddrVerifier);

}  // namespace

}  // namespace proofs
