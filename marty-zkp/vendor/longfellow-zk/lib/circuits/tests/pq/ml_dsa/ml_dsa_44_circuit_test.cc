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

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "algebra/fp24.h"
#include "algebra/fp24_6.h"
#include "algebra/reed_solomon_extension.h"
#include "arrays/dense.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_examples.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_types.h"
#include "circuits/tests/pq/ml_dsa/ml_dsa_44_witness.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/circuit.h"
#include "util/log.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace ml_dsa {
namespace {

using BaseField = Fp24;
using Field6 = Fp24_6;
using CBK = CompilerBackend<Field6>;
using LogicCircuit = Logic<Field6, CBK>;
using VerifyCircuit = MLDSA44Verify<LogicCircuit, Field6>;

constexpr uint32_t kBeta = 7;

template <typename F>
std::unique_ptr<Circuit<Field6>> build_ml_dsa_44_circuit(size_t nc,
                                                         const char* name,
                                                         F f) {
  const Field6 f6 = Field6(ml_dsa::Fq, kBeta);

  QuadCircuit<Field6> Q(f6);
  const CBK cbk(&Q);
  const LogicCircuit LC(&cbk, f6);
  VerifyCircuit verify(LC);

  f(Q, LC, verify);

  auto CIRCUIT = Q.mkcircuit(nc);
  dump_info(name, Q);
  return CIRCUIT;
}

std::unique_ptr<Circuit<Field6>> make_ml_dsa_44_circuit(size_t nc) {
  return build_ml_dsa_44_circuit(
      nc, "ml_dsa_44_valid_signature_on_mu",
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        auto pk = std::make_unique<VerifyCircuit::Pk>();
        pk->input(LC);

        Q.private_input();
        auto sig = std::make_unique<VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<VerifyCircuit::Witness>();
        // c_tilde: H(mu || w1). mu=64, w1=768. Total 832 --> 7 blocks.
        w->c_prime_tilde_bws_.resize(7);

        w->input(LC);

        // Dummy message
        std::array<LogicCircuit::v8, 64> mu;
        for (size_t i = 0; i < 64; ++i) {
          mu[i] = LC.vinput<8>();
        }

        verify.assert_valid_signature_on_mu(*pk, *sig, mu, *w);
      });
}

std::unique_ptr<Circuit<Field6>> make_ml_dsa_44_sampleinball_circuit(
    size_t nc) {
  return build_ml_dsa_44_circuit(
      nc, "ml_dsa_44_sample_in_ball",
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        std::array<LogicCircuit::v8, 32> rho;
        for (size_t i = 0; i < 32; ++i) {
          rho[i] = LC.vinput<8>();
        }

        Q.private_input();

        VerifyCircuit::RqW cprime;
        cprime.input(LC);

        VerifyCircuit::SampleInBallWitness witness;
        witness.input(LC);

        verify.assert_sample_in_ball(rho, cprime, witness);
      });
}

std::unique_ptr<Circuit<Field6>> make_ml_dsa_44_w_prime_approx_circuit(
    size_t nc) {
  return build_ml_dsa_44_circuit(
      nc, "ml_dsa_44_w_prime_approx",
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        auto pk = std::make_unique<VerifyCircuit::Pk>();
        pk->input(LC);

        Q.private_input();
        auto sig = std::make_unique<VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<VerifyCircuit::Witness>();
        w->c_prime_tilde_bws_.resize(7);

        w->input(LC);

        verify.assert_w_prime_approx(*pk, *sig, *w);
      });
}

std::unique_ptr<Circuit<Field6>> make_ml_dsa_44_use_hint_circuit(size_t nc) {
  return build_ml_dsa_44_circuit(
      nc, "ml_dsa_44_use_hint",
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        Q.private_input();
        auto sig = std::make_unique<VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<VerifyCircuit::Witness>();
        w->input(LC);

        verify.assert_use_hint(sig->h, w->w_prime_approx_, w->w1_,
                               w->hint_aux_bits_, w->w_prime_1_,
                               w->w_prime_1_bits_, w->h_sum_bits_);
      });
}

std::unique_ptr<Circuit<Field6>> make_ml_dsa_44_ctilde_circuit(size_t nc) {
  return build_ml_dsa_44_circuit(
      nc, "ml_dsa_44_ctilde",
      [](QuadCircuit<Field6>& Q, const LogicCircuit& LC,
         VerifyCircuit& verify) {
        Q.private_input();
        auto sig = std::make_unique<VerifyCircuit::SignatureW>();
        sig->input(LC);

        auto w = std::make_unique<VerifyCircuit::Witness>();
        w->c_prime_tilde_bws_.resize(7);
        w->input(LC);

        // Dummy message
        std::array<LogicCircuit::v8, 64> mu;
        for (size_t i = 0; i < 64; ++i) {
          mu[i] = LC.vinput<8>();
        }

        verify.assert_ctilde(mu, w->w1_tilde_, w->c_prime_tilde_bws_,
                             sig->c_tilde);
      });
}

TEST(MlDsa44CircuitTest, SampleInBallCircuitSize) {
  auto CIRCUIT = make_ml_dsa_44_sampleinball_circuit(1);
}

TEST(MlDsa44CircuitTest, WPrimeApproxCircuitSize) {
  auto CIRCUIT = make_ml_dsa_44_w_prime_approx_circuit(1);
}

TEST(MlDsa44CircuitTest, UseHintCircuitSize) {
  auto CIRCUIT = make_ml_dsa_44_use_hint_circuit(1);
}

TEST(MlDsa44CircuitTest, CTildeCircuitSize) {
  auto CIRCUIT = make_ml_dsa_44_ctilde_circuit(1);
}

struct ProverEnv {
  const Field6& f;
  std::unique_ptr<Circuit<Field6>> circuit;
  ReedSolomonExtensionFactory rsextf;
  ml_dsa_44_witness witness_gen;
  std::unique_ptr<ZkProof<Field6>> zkpr;
  Dense<Field6> w;
  ZkProver<Field6, ReedSolomonExtensionFactory> prover;
  Transcript tp;
  SecureRandomEngine rng;

  explicit ProverEnv(const Field6& f6)
      : f(f6),
        circuit(make_ml_dsa_44_circuit(1)),
        rsextf(ml_dsa::Fq),
        w(1, circuit->ninputs),
        prover(*circuit, f, rsextf),
        tp((uint8_t*)"test", 4) {
    auto tests = GetMlDsa44Examples();
    const auto& test = tests[0];
    witness_gen.compute_witness(test.pkey, test.sig, test.msg, test.ctx);

    zkpr = std::make_unique<ZkProof<Field6>>(*circuit, 4, 128);
    DenseFiller<Field6> filler(w);
    filler.push_back(f.one());
    witness_gen.fill_witness(filler, f);

    for (size_t i = 0; i < 64; ++i) {
      filler.push_back(witness_gen.mu_[i], 8, f);
    }
  }
};

TEST(MlDsa44CircuitTest, AssertValidSignatureOnMu) {
  const Field6 f = Field6(ml_dsa::Fq, kBeta);
  ProverEnv env(f);

  env.prover.commit(*env.zkpr, env.w, env.tp, env.rng);
  bool ok = env.prover.prove(*env.zkpr, env.w, env.tp);
  EXPECT_TRUE(ok) << "Failed to prove witness for test case ";

  ZkVerifier<Field6, ReedSolomonExtensionFactory> verifier(
      *env.circuit, env.rsextf, 4, 128, env.f);
  Transcript tv((uint8_t*)"test", 4);
  verifier.recv_commitment(*env.zkpr, tv);
  Dense<Field6> pub(1, env.circuit->ninputs);  // Empty public inputs
  DenseFiller<Field6> vfiller(pub);
  vfiller.push_back(env.f.one());
  env.witness_gen.fill_pk(vfiller, env.f);

  bool ok2 = verifier.verify(*env.zkpr, pub, tv);
  EXPECT_TRUE(ok2) << "Failed to verify witness for test case ";
}

void BM_MLDSA44ZK_Prove(benchmark::State& state) {
  set_log_level(ERROR);
  const Field6& f = Field6(ml_dsa::Fq, kBeta);

  ProverEnv env(f);

  for (auto s : state) {
    env.prover.commit(*env.zkpr, env.w, env.tp, env.rng);
    env.prover.prove(*env.zkpr, env.w, env.tp);
    benchmark::DoNotOptimize(env.zkpr);
  }
}
BENCHMARK(BM_MLDSA44ZK_Prove);

}  // namespace
}  // namespace ml_dsa
}  // namespace proofs
