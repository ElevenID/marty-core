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

#include "circuits/tests/ec/pk_circuit.h"

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
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "circuits/tests/ec/pk_witness.h"
#include "ec/p256.h"
#include "ec/p256k1.h"
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
// ZK parameters
constexpr size_t kRate = 4;
constexpr size_t kQueries = 128;

struct P256Traits {
  using Field = Fp256Base;
  using Scalar = Fp256Scalar;
  using EC = P256;

  static const EC& ec() { return p256; }
  static const Field& field() { return p256_base; }
  static const Scalar& scalar_field() { return p256_scalar; }
};

struct P256K1Traits {
  using Field = Fp256k1Base;
  using Scalar = Fp256k1Scalar;
  using EC = P256k1;

  static const EC& ec() { return p256k1; }
  static const Field& field() { return p256k1_base; }
  static const Scalar& scalar_field() { return p256k1_scalar; }
};

template <typename Traits>
class EcpkTest : public ::testing::Test {
 public:
  using Field = typename Traits::Field;
  using Scalar = typename Traits::Scalar;
  using EC = typename Traits::EC;
  using Nat = typename Field::N;
  using Elt = typename Field::Elt;

  // Logic types
  using EvalBackend = EvaluationBackend<Field>;
  using LogicType = Logic<Field, EvalBackend>;
  using EltW = typename LogicType::EltW;
  using EcpkC = Ecpk<LogicType, Field, EC>;
  using PkW = PkWitness<EC, Scalar>;

  // Compiler types
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltWC = typename LogicCircuit::EltW;
  using EcpkCC = Ecpk<LogicCircuit, Field, EC>;
  void CheckRelation(const Nat& sk_nat, const typename EC::ECPoint& PK,
                     bool expected) {
    const Field& F = Traits::field();
    const EC& ec = Traits::ec();
    const Scalar& scalar = Traits::scalar_field();

    const EvalBackend ebk(F, expected);
    const LogicType l(&ebk, F);

    EcpkC circuit(l, ec);
    PkW wit_gen(scalar, ec);

    EXPECT_TRUE(wit_gen.compute_witness(sk_nat));

    EltW pk_x = l.konst(PK.x);
    EltW pk_y = l.konst(PK.y);

    typename EcpkC::Witness w;
    for (size_t j = 0; j < EC::kBits; ++j) {
      w.bits[j] = l.konst(wit_gen.bits_[j]);
      if (j < EC::kBits - 1) {
        w.int_x[j] = l.konst(wit_gen.int_x_[j]);
        w.int_y[j] = l.konst(wit_gen.int_y_[j]);
        w.int_z[j] = l.konst(wit_gen.int_z_[j]);
      }
    }

    circuit.assert_public_key(pk_x, pk_y, w);
    if (expected) {
      ASSERT_FALSE(ebk.assertion_failed());
    } else {
      ASSERT_TRUE(ebk.assertion_failed());
    }
  }

  // Test for a particular attack in which (0,0,0) is provided as the
  // intermediate witness values.  This test should always fail.
  void CheckRelationZeroWitness(const Nat& sk_nat,
                                const typename EC::ECPoint& PK) {
    const Field& F = Traits::field();
    const EC& ec = Traits::ec();
    const Scalar& scalar = Traits::scalar_field();

    const EvalBackend ebk(F, false);
    const LogicType l(&ebk, F);

    EcpkC circuit(l, ec);
    PkW wit_gen(scalar, ec);

    // Compute the real witness.
    EXPECT_TRUE(wit_gen.compute_witness(sk_nat));

    EltW pk_x = l.konst(PK.x);
    EltW pk_y = l.konst(PK.y);

    // Set the intermediate witness values to 0.
    typename EcpkC::Witness w;
    for (size_t j = 0; j < EC::kBits; ++j) {
      w.bits[j] = l.konst(wit_gen.bits_[j]);
      if (j < EC::kBits - 1) {
        w.int_x[j] = l.konst(F.zero());
        w.int_y[j] = l.konst(F.zero());
        w.int_z[j] = l.konst(F.zero());
      }
    }

    circuit.assert_public_key(pk_x, pk_y, w);
    ASSERT_TRUE(ebk.assertion_failed());
  }
};

TYPED_TEST_SUITE_P(EcpkTest);

TYPED_TEST_P(EcpkTest, VerifyRelation) {
  using Field = typename TypeParam::Field;
  using EC = typename TypeParam::EC;
  using Nat = typename Field::N;

  const EC& ec = TypeParam::ec();

  for (int i = 0; i < 5; ++i) {
    Nat sk_nat = Nat(9876543219999 + i);
    auto PK = ec.scalar_multf(ec.generator(), sk_nat);
    ec.normalize(PK);

    this->CheckRelation(sk_nat, PK, true);
  }
}

TYPED_TEST_P(EcpkTest, VerifyFailure) {
  using Field = typename TypeParam::Field;
  using Scalar = typename TypeParam::Scalar;
  using EC = typename TypeParam::EC;
  using Nat = typename Field::N;

  const EC& ec = TypeParam::ec();
  const Scalar& scalar = TypeParam::scalar_field();

  Nat sk_nat = Nat(123456);

  Nat sk_plus_one = sk_nat;
  scalar.add(sk_plus_one, Nat(1));
  auto PK_wrong = ec.scalar_multf(ec.generator(), sk_plus_one);
  ec.normalize(PK_wrong);

  this->CheckRelation(sk_nat, PK_wrong, false);
}

TYPED_TEST_P(EcpkTest, VerifyZeroWitnessFailure) {
  using Field = typename TypeParam::Field;
  using EC = typename TypeParam::EC;
  using Nat = typename Field::N;

  const EC& ec = TypeParam::ec();

  Nat sk_nat = Nat(123456);

  auto PK = ec.scalar_multf(ec.generator(), sk_nat);
  ec.normalize(PK);

  this->CheckRelationZeroWitness(sk_nat, PK);
}

TYPED_TEST_P(EcpkTest, CircuitSize) {
  using Field = typename TypeParam::Field;
  using EC = typename TypeParam::EC;
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using EcpkC = Ecpk<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(TypeParam::field());
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, TypeParam::field());
  EcpkC circuit(lc, TypeParam::ec());

  typename EcpkC::Witness w;
  w.input(lc);
  EltW pk_x = lc.eltw_input();
  EltW pk_y = lc.eltw_input();

  circuit.assert_public_key(pk_x, pk_y, w);
  auto CIRCUIT = Q.mkcircuit(1);
  dump_info("ecpk verify", Q);
}

// Helpers for ZK Test
template <typename Traits>
std::unique_ptr<Circuit<typename Traits::Field>> make_circuit(size_t numKeys) {
  using Field = typename Traits::Field;
  using EC = typename Traits::EC;
  using CompilerBackendType = CompilerBackend<Field>;
  using LogicCircuit = Logic<Field, CompilerBackendType>;
  using EltW = typename LogicCircuit::EltW;
  using EcpkC = Ecpk<LogicCircuit, Field, EC>;

  QuadCircuit<Field> Q(Traits::field());
  const CompilerBackendType cbk(&Q);
  const LogicCircuit lc(&cbk, Traits::field());
  EcpkC circuit(lc, Traits::ec());

  std::vector<typename EcpkC::Witness> ws(numKeys);
  std::vector<EltW> pkxs(numKeys);
  std::vector<EltW> pkys(numKeys);

  for (size_t i = 0; i < numKeys; ++i) {
    pkxs[i] = lc.eltw_input();
    pkys[i] = lc.eltw_input();
  }

  Q.private_input();
  for (size_t i = 0; i < numKeys; ++i) {
    ws[i].input(lc);
  }

  for (size_t i = 0; i < numKeys; ++i) {
    circuit.assert_public_key(pkxs[i], pkys[i], ws[i]);
  }
  return Q.mkcircuit(1);
}

template <typename Traits>
void fill_input(Dense<typename Traits::Field>& W, size_t numSigs, bool prover) {
  using Field = typename Traits::Field;
  using EC = typename Traits::EC;
  using Scalar = typename Traits::Scalar;
  using Nat = typename Field::N;
  using PkW = PkWitness<EC, Scalar>;

  const auto& ec = Traits::ec();
  const auto& scalar = Traits::scalar_field();
  const auto& field = Traits::field();

  PkW wit_gen(scalar, ec);
  DenseFiller<Field> filler(W);
  filler.push_back(field.one());

  Nat sk = Nat(123456789);
  auto PK = ec.scalar_multf(ec.generator(), sk);
  ec.normalize(PK);
  wit_gen.compute_witness(sk);

  for (size_t i = 0; i < numSigs; ++i) {
    filler.push_back(PK.x);
    filler.push_back(PK.y);
  }

  if (prover) {
    for (size_t i = 0; i < numSigs; ++i) {
      wit_gen.fill_witness(filler);
    }
  }
}

TYPED_TEST_P(EcpkTest, ZkProverVerifier) {
  using Field = typename TypeParam::Field;

  set_log_level(INFO);
  size_t numSigs = 1;
  auto CIRCUIT = make_circuit<TypeParam>(numSigs);
  auto W = std::make_unique<Dense<Field>>(1, CIRCUIT->ninputs);
  fill_input<TypeParam>(*W, numSigs, true);

  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  ConvolutionFactory factory(TypeParam::field());
  RSFactory rsf(factory, TypeParam::field());

  Transcript tp((uint8_t*)"zkproververifier", 16);
  SecureRandomEngine rng;

  ZkProof<Field> zkpr(*CIRCUIT, kRate, kQueries);
  ZkProver<Field, RSFactory> prover(*CIRCUIT, TypeParam::field(), rsf);
  prover.commit(zkpr, *W, tp, rng);
  prover.prove(zkpr, *W, tp);
  log(INFO, "Prover done");

  Transcript tv((uint8_t*)"zkproververifier", 16);
  auto pub = Dense<Field>(1, CIRCUIT->npub_in);
  fill_input<TypeParam>(pub, numSigs, false);

  ZkVerifier<Field, RSFactory> verifier(*CIRCUIT, rsf, kRate, kQueries,
                                        TypeParam::field());
  verifier.recv_commitment(zkpr, tv);
  EXPECT_TRUE(verifier.verify(zkpr, pub, tv));
  log(INFO, "Verifier done");
}

REGISTER_TYPED_TEST_SUITE_P(EcpkTest, VerifyRelation, VerifyFailure,
                            VerifyZeroWitnessFailure, CircuitSize,
                            ZkProverVerifier);

using TestTypes = ::testing::Types<P256Traits, P256K1Traits>;
INSTANTIATE_TYPED_TEST_SUITE_P(P256, EcpkTest, TestTypes);

// ===================== Benchmarks ==============================

template <typename Traits>
struct BenchmarkContext {
  using Field = typename Traits::Field;
  using Crt = CRT256<Field>;
  using ConvolutionFactory = CrtConvolutionFactory<Crt, Field>;
  using RSFactory = ReedSolomonFactory<Field, ConvolutionFactory>;

  std::unique_ptr<Circuit<Field>> circuit;
  Dense<Field> w;
  ConvolutionFactory factory;
  RSFactory rsf;
  Transcript tp;
  SecureRandomEngine rng;
  ZkProof<Field> zkpr;
  ZkProver<Field, RSFactory> prover;

  explicit BenchmarkContext(size_t numKeys)
      : circuit(make_circuit<Traits>(numKeys)),
        w(1, circuit->ninputs),
        factory(Traits::field()),
        rsf(factory, Traits::field()),
        tp((uint8_t*)"benchmark", 9),
        zkpr(*circuit, kRate, kQueries),
        prover(*circuit, Traits::field(), rsf) {
    set_log_level(ERROR);
    fill_input<Traits>(w, numKeys, true);
  }
};

template <typename Traits>
void BM_EcpkProverTemplate(benchmark::State& state) {
  BenchmarkContext<Traits> ctx(state.range(0));
  for (auto s : state) {
    ctx.prover.commit(ctx.zkpr, ctx.w, ctx.tp, ctx.rng);
    ctx.prover.prove(ctx.zkpr, ctx.w, ctx.tp);
  }
}

template <typename Traits>
void BM_EcpkVerifierTemplate(benchmark::State& state) {
  using Field = typename Traits::Field;
  BenchmarkContext<Traits> ctx(state.range(0));
  ctx.prover.commit(ctx.zkpr, ctx.w, ctx.tp, ctx.rng);
  ctx.prover.prove(ctx.zkpr, ctx.w, ctx.tp);

  ZkVerifier<Field, typename BenchmarkContext<Traits>::RSFactory> verifier(
      *ctx.circuit, ctx.rsf, kRate, kQueries, Traits::field());

  auto pub = Dense<Field>(1, ctx.circuit->npub_in);
  fill_input<Traits>(pub, state.range(0), false);

  for (auto s : state) {
    Transcript tv((uint8_t*)"benchmark", 9);
    verifier.recv_commitment(ctx.zkpr, tv);
    verifier.verify(ctx.zkpr, pub, tv);
  }
}

void BM_EcpkProver_P256(benchmark::State& state) {
  BM_EcpkProverTemplate<P256Traits>(state);
}
BENCHMARK(BM_EcpkProver_P256)->DenseRange(1, 4);

void BM_EcpkVerifier_P256(benchmark::State& state) {
  BM_EcpkVerifierTemplate<P256Traits>(state);
}
BENCHMARK(BM_EcpkVerifier_P256)->DenseRange(1, 4);

void BM_EcpkProver_P256K1(benchmark::State& state) {
  BM_EcpkProverTemplate<P256K1Traits>(state);
}
BENCHMARK(BM_EcpkProver_P256K1)
    ->DenseRange(1, 2);  // Reduced range due to slowness

void BM_EcpkVerifier_P256K1(benchmark::State& state) {
  BM_EcpkVerifierTemplate<P256K1Traits>(state);
}
BENCHMARK(BM_EcpkVerifier_P256K1)->DenseRange(1, 2);

}  // namespace proofs
