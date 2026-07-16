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

#include "ec/elliptic_curve.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "algebra/fp.h"
#include "ec/p256.h"
#include "ec/p256k1.h"
#include "benchmark/benchmark.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
constexpr size_t W = 4;
typedef Fp<4, true> Field;

const Field f_32543(
    "1056598764504768070153408279638907619769800489"
    "86351025435035631207814085532543");

const Field f_53951(
    "0xFFFFFFFF00000001000000000000000000000000FFFF"
    "FFFFFFFFFFFFFFFFFFFF");

typedef EllipticCurve<Field, 4, 256> EC32543;
typedef EllipticCurve<Field, 4, 256> EC53951;

// The following curve from https://arxiv.org/pdf/2208.01635.pdf has prime
// order =
// 105659876450476807015340827963890761976544313325663770762399235394744121359871.
const EC32543 ec_32543(
    f_32543.of_string("57780130698115176583488499171344771088898507337873238590"
                      "400955371129685138826"),
    f_32543.of_string("10245195084107374794931679649589693796070211548697536379"
                      "8323596797327090813462"),
    f_32543.of_string("53851663331146464978109980746124159858219863711514859545"
                      "86014078688791960064"),
    f_32543.of_string("88440166531789946723126083546750633179866039092883764784"
                      "041611065547926159080"),
    f_32543);

const EC53951 ec_53951(
    f_53951.of_string(
        "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
    f_53951.of_string(
        "0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"),
    f_53951.of_string(
        "0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
    f_53951.of_string(
        "0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5"),
    f_53951);

TEST(EllipticCurve, isOnCurve) {
  EXPECT_TRUE(ec_32543.is_on_curve(ec_32543.generator()));
  EXPECT_TRUE(ec_32543.is_on_curve(ec_32543.zero()));

  EXPECT_TRUE(ec_53951.is_on_curve(ec_53951.generator()));
  EXPECT_TRUE(ec_53951.is_on_curve(ec_53951.zero()));

  EXPECT_TRUE(p256k1.is_on_curve(p256k1.generator()));
  EXPECT_TRUE(p256k1.is_on_curve(p256k1.zero()));

  // This point is on the curve, but not normalized, and thus our method
  // should return false.
  EXPECT_FALSE(ec_32543.is_on_curve(EC32543::ECPoint(
      f_32543.of_scalar(6),
      f_32543.of_string("175192863081551057610611323522603468882267323925296967"
                        "51295234077254554968800"),
      f_32543.of_scalar(2))));

  auto p = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561173"));
  EXPECT_FALSE(ec_32543.equal(p, ec_32543.zero()));

  auto mp = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("167151314019692867652783211567275353146303951050925488"
                        "83650844735804900971370"));
  EXPECT_FALSE(ec_32543.equal(mp, ec_32543.zero()));

  EXPECT_FALSE(ec_32543.is_on_curve(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561172")));
}

// Test with secp256k1 where a = 0, b = 7.
TEST(EllipticCurve, addEZeroA) {
  // Compute in sagemath and check the result with our code.
  // Use the secp256k1 curve.
  // p  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  // F  = FiniteField(p)
  // E  = EllipticCurve(F, [0, 7])
  // G  =
  // E(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
  // 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
  // # this is the order of the elliptic curve group
  // n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  // Fn = FiniteField(n)

  // P1 = G * 10 =
  // (72488970228380509287422715226575535698893157273063074627791787432852706183111
  // 62070622898698443831883535403436258712770888294397026493185421712108624767191
  // 1)
  // P2 = G * 12412 =
  // (52879966086176162108240354162378292947425517669095498736796738054975791823498
  // 30699390762290600754781212069883870270938814099133957400920709995153465021145
  // 1)
  // P1+P2 =
  // (100032783050058150499785349038845742794401895778389296862674788824339876696454
  // 24893872525273665559647505993700238432595500474576223152737037560633815418477
  // 1)

  auto p1 =
      p256k1.point(p256k1_base.of_string(
                       "7248897022838050928742271522657553569889315727306307"
                       "4627791787432852706183111"),
                   p256k1_base.of_string(
                       "6207062289869844383188353540343625871277088829439702"
                       "6493185421712108624767191"));
  auto p2 =
      p256k1.point(p256k1_base.of_string(
                       "5287996608617616210824035416237829294742551766909549"
                       "8736796738054975791823498"),
                   p256k1_base.of_string(
                       "3069939076229060075478121206988387027093881409913395"
                       "7400920709995153465021145"));
  auto want =
      p256k1.point(p256k1_base.of_string(
                       "1000327830500581504997853490388457427944018957783892"
                       "96862674788824339876696454"),
                   p256k1_base.of_string(
                       "2489387252527366555964750599370023843259550047457622"
                       "3152737037560633815418477"));

  auto got = p256k1.addEf(p1, p2);
  EXPECT_TRUE(p256k1.equal(want, got));

  // may as well test commutativity:
  got = p256k1.addEf(p2, p1);
  EXPECT_TRUE(p256k1.equal(want, got));

  // test with infinity point.
  auto z = p256k1.zero();
  got = p256k1.addEf(z, p1);
  EXPECT_TRUE(p256k1.equal(p1, got));
  got = p256k1.addEf(p1, z);
  EXPECT_TRUE(p256k1.equal(p1, got));

  // test overwrite value
  p256k1.addE(p1, p2);
  EXPECT_TRUE(p256k1.equal(want, p1));
}

// Test with secp256k1 where a = 0, b = 7.
TEST(EllipticCurve, doubleEZeroA) {
  auto p1 =
      p256k1.point(p256k1_base.of_string(
                       "1073035822907330979248421939724650220531482117751943"
                       "73671539518313500194639752"),
                   p256k1_base.of_string(
                       "1037959661087827174468066840237421684623654492726397"
                       "90795591544606836007446638"));

  auto want =
      p256k1.point(p256k1_base.of_string(
                       "9288356354773395374719339924146797529520150860835279"
                       "8513009429659680796014075"),
                   p256k1_base.of_string(
                       "1146109652104331348038103431792376352806630981117018"
                       "48326472592228175073260197"));

  auto got = p256k1.doubleEf(p1);
  EXPECT_TRUE(p256k1.equal(want, got));

  // // test with infinity point.
  auto z = p256k1.zero();
  got = p256k1.doubleEf(z);
  EXPECT_TRUE(p256k1.equal(got, z));
}

// Test with secp256r1 curve where a = -3.
TEST(EllipticCurve, addEMinus3A) {
  auto p1 = ec_53951.point(
      f_53951.of_string("565152197906911714131090579040116886954248101558029299"
                        "73526481321309856242040"),
      f_53951.of_string("337703184371225825922371145149145259808867551975154856"
                        "7112458094635497583569"));
  auto p2 = ec_53951.point(
      f_53951.of_string("112408679900023231809246133755790494075208376728748483"
                        "995370618426422155115628"),
      f_53951.of_string("498237100143848652850565955106356993462945737819513433"
                        "11221423895961832974253"));
  auto want = ec_53951.point(
      f_53951.of_string("111694352951862023542776309354414877394027736966010471"
                        "01735900939923127703960"),
      f_53951.of_string("786055119933597043243514268547451740551314242791577376"
                        "91618238984203071285154"));

  auto got = ec_53951.addEf(p1, p2);
  EXPECT_TRUE(ec_53951.equal(want, got));
}

// Test with secp256r1 curve where a = -3.
TEST(EllipticCurve, doubleEMinus3A) {
  auto p1 = ec_53951.point(
      f_53951.of_string("112408679900023231809246133755790494075208376728748483"
                        "995370618426422155115628"),
      f_53951.of_string("498237100143848652850565955106356993462945737819513433"
                        "11221423895961832974253"));
  auto want = ec_53951.point(
      f_53951.of_string("885884674782654900235199359821876275484611260577767040"
                        "31032323803350375021520"),
      f_53951.of_string("767985716630533603779391244706390556201037096191808849"
                        "9728736832660268223620"));

  ec_53951.doubleE(p1);
  EXPECT_TRUE(ec_53951.equal(want, p1));
}

// Test with random curve using the general formula.
TEST(EllipticCurve, addEGeneral) {
  // G * 12
  auto p12 = ec_32543.point(
      f_32543.of_string("134808783667219648189263450305873688991251945654246752"
                        "22390028645041219938745"),
      f_32543.of_string("100527482324383093851451454237191654885134853280983427"
                        "210888648347852121150952"));
  // G * 4321
  auto p4321 = ec_32543.point(
      f_32543.of_string("329130036724930002544976288399195578354103016201810384"
                        "63262550483453294324440"),
      f_32543.of_string("546743602120459044951591654595765404409913799377625317"
                        "5279966440418856665708"));
  auto want = ec_32543.point(
      f_32543.of_string("700549381434284036627210001211630287911988690360413711"
                        "71252986977253437280559"),
      f_32543.of_string("602279424320787220776145802808248329062258408707344429"
                        "87846067237162092805952"));

  auto got = ec_32543.addEf(p12, p4321);
  EXPECT_TRUE(ec_32543.equal(want, got));

  // Verify addition with itself.
  auto want24 = ec_32543.point(
      f_32543.of_string("103731248137202420387366645061627197035273436337246178"
                        "882638115333015475963392"),
      f_32543.of_string("161231444099616023998514916519220697509776202121636011"
                        "25130907480358991149046"));
  auto got24 = ec_32543.addEf(p12, p12);
  EXPECT_TRUE(ec_32543.equal(want24, got24));

  // Verify addition with neg.
  auto pn12 = ec_32543.point(
      f_32543.of_string("134808783667219648189263450305873688991251945654246752"
                        "22390028645041219938745"),
      f_32543.of_string("513239412609371316388937372669910709184519570536759822"
                        "4146982859961964381591"));
  auto gotn = ec_32543.addEf(p12, pn12);
  EXPECT_TRUE(ec_32543.equal(ec_32543.zero(), gotn));

  // Verify addition with Inf.
  auto gotz = ec_32543.addEf(p12, ec_32543.zero());
  EXPECT_TRUE(ec_32543.equal(p12, gotz));
  gotz = ec_32543.addEf(ec_32543.zero(), p12);
  EXPECT_TRUE(ec_32543.equal(p12, gotz));

  {  // test that (i+j)*a+j*b = i*a+j*(a+b)
    auto a = p12;
    auto b = want24;
    auto apb = ec_32543.addEf(a, b);
    for (size_t i = 0; i < 10; ++i) {
      for (size_t j = 0; j < 10; ++j) {
        auto aipj = ec_32543.scalar_multf(a, EC32543::N(i + j));
        auto ai = ec_32543.scalar_multf(a, EC32543::N(i));
        auto bj = ec_32543.scalar_multf(b, EC32543::N(j));
        auto apbj = ec_32543.scalar_multf(apb, EC32543::N(j));
        EXPECT_TRUE(
            ec_32543.equal(ec_32543.addEf(aipj, bj), ec_32543.addEf(ai, apbj)));
      }
    }
  }
}

// Test with random curve using the general formula.
TEST(EllipticCurve, doubleEGeneral) {
  auto p1 = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561173"));
  auto want = ec_32543.point(
      f_32543.of_string("509017422813935192393111620289104455654561113237332808"
                        "7715939287642942312136"),
      f_32543.of_string("834726355457066002594785096169403344896585204779436918"
                        "80323533707461094248605"));

  auto got = ec_32543.doubleEf(p1);
  EXPECT_TRUE(ec_32543.equal(want, got));

  auto zero = ec_32543.zero();
  auto gotz = ec_32543.doubleEf(zero);
  EXPECT_TRUE(ec_32543.equal(zero, gotz));

  /* Double is also tested in the addGeneral tests above. */
}

TEST(EllipticCurve, P256MultiExponentiation) {
  auto g = p256.generator();

  std::mt19937 rng;
  std::uniform_int_distribution<uint64_t> dist;

  constexpr size_t n = 1000;
  std::vector<P256::ECPoint> p(n);
  std::vector<P256::N> s(n);
  {
    // Test default case.
    auto got = p256.scalar_multf(0, &p[0], &s[0]);
    EXPECT_TRUE(p256.equal(p256.zero(), got));
  }

  {
    auto want = p256.zero();
    for (size_t i = 0; i < n; ++i) {
      if (i == 0) {
        p[i] = g;
      } else {
        p[i] = p256.doubleEf(p[i - 1]);
      }
      std::array<uint64_t, W> init;
      for (size_t j = 0; j < W; ++j) {
        init[j] = dist(rng);
      }
      s[i] = P256::N(init);
      want = p256.addEf(want, p256.scalar_multf(p[i], s[i]));
    }

    auto got = p256.scalar_multf(n, &p[0], &s[0]);
    EXPECT_TRUE(p256.equal(want, got));
  }

  // now test the screw case of one large exponent and a bunch of
  // small exponents, where the Bernstein variant
  // (https://cr.yp.to/badbatch/boscoster2.py) takes forever
  // because it runs
  //     for (s=0xdeadbeefabadcafe; s > 0; s--) {...}
  {
    auto want = p256.zero();
    for (size_t i = 0; i < n; ++i) {
      if (i == 0) {
        p[i] = g;
        s[i] = P256::N(0xdeadbeefabadcafe);
      } else {
        p[i] = p256.doubleEf(p[i - 1]);
        s[i] = P256::N(1);
      }
      want = p256.addEf(want, p256.scalar_multf(p[i], s[i]));
    }

    auto got = p256.scalar_multf(n, &p[0], &s[0]);
    EXPECT_TRUE(p256.equal(want, got));
  }

  {
    p[0] = p256.generator();
    s[0] = P256::N(1);
    auto want = p[0];
    auto got = p256.scalar_multf(1, &p[0], &s[0]);
    EXPECT_TRUE(p256.equal(want, got));
  }
}

TEST(EllipticCurve, P256k1MultiExponentiation) {
  auto g = p256k1.generator();

  std::mt19937 rng;
  std::uniform_int_distribution<uint64_t> dist;

  constexpr size_t n = 100;
  std::vector<P256k1::ECPoint> p(n);
  std::vector<P256k1::N> s(n);
  {
    // Test default case.
    auto got = p256k1.scalar_multf(0, &p[0], &s[0]);
    EXPECT_TRUE(p256k1.equal(p256k1.zero(), got));
  }

  {
    auto want = p256k1.zero();
    for (size_t i = 0; i < n; ++i) {
      if (i == 0) {
        p[i] = g;
      } else {
        p[i] = p256k1.doubleEf(p[i - 1]);
      }
      std::array<uint64_t, 4> init;
      for (size_t j = 0; j < 4; ++j) {
        init[j] = dist(rng);
      }
      s[i] = P256k1::N(init);
      want = p256k1.addEf(want, p256k1.scalar_multf(p[i], s[i]));
    }

    auto got = p256k1.scalar_multf(n, &p[0], &s[0]);
    EXPECT_TRUE(p256k1.equal(want, got));
  }
}

// ============================= Benchmarks ================================

void BM_add_p256(benchmark::State& state) {
  auto p = p256.generator();

  for (auto _ : state) {
    p256.addE(p, p);
  }
}
BENCHMARK(BM_add_p256);

void BM_add(benchmark::State& state) {
  auto p = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561173"));
  auto p2 = ec_32543.addEf(p, p);

  for (auto _ : state) {
    ec_32543.addE(p2, p);
  }
}
BENCHMARK(BM_add);

void BM_double(benchmark::State& state) {
  auto p = ec_32543.generator();

  for (auto _ : state) {
    ec_32543.doubleE(p);
  }
}
BENCHMARK(BM_double);

void BM_scalar(benchmark::State& state) {
  using N = EC32543::N;
  auto p = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561173"));

  N n("377732104077222810948432467983836545945051582234611510526750448658884410"
      "8848");
  for (auto _ : state) {
    p = ec_32543.scalar_multf(p, n);
  }
}
BENCHMARK(BM_scalar);

void BM_commit(benchmark::State& state) {
  auto p = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561173"));

  using N = EC32543::N;
  N n("377732104077222810948432467983836545945051582234611510526750448658884410"
      "8848");

  auto r = ec_32543.zero();

  size_t LEN = state.range(0);
  for (auto _ : state) {
    for (size_t j = 0; j < LEN; ++j) {
      p = ec_32543.scalar_multf(p, n);
      ec_32543.addE(r, p);
    }
  }
}
BENCHMARK(BM_commit)->Range(1 << 10, 1 << 22);

void BM_multiexp(benchmark::State& state) {
  auto g = ec_32543.point(
      f_32543.of_string("104494200016653967385948977022237419181744316220626192"
                        "507506027505728800092025"),
      f_32543.of_string("889447450485075202500625068071632266623496538812584765"
                        "51384786472009184561173"));
  size_t n = state.range(0);

  std::mt19937 rng;
  std::uniform_int_distribution<uint64_t> dist;

  using ECPoint = EC32543::ECPoint;
  using N = EC32543::N;

  std::vector<ECPoint> p(n);
  std::vector<ECPoint> p1(n);
  std::vector<N> s(n);
  std::vector<N> s1(n);

  // Generate random inputs for multi-exp.
  p[0] = g;
  s[0] = N(1);
  for (size_t i = 1; i < n; ++i) {
    p[i] = ec_32543.doubleEf(p[i - 1]);
    std::array<uint64_t, N::kU64> init;
    for (size_t j = 0; j < N::kU64; ++j) {
      init[j] = dist(rng);
    }
    s[i] = N(init);
  }

  for (auto _ : state) {
    // Need to copy inputs, because scalar_multf consumes them.
    for (size_t i = 0; i < n; ++i) {
      p1[i] = p[i];
      s1[i] = s[i];
    }
    ec_32543.scalar_multf(n, &p1[0], &s1[0]);
  }
}
BENCHMARK(BM_multiexp)->RangeMultiplier(4)->Range(1 << 10, 1 << 22);

}  // namespace
}  // namespace proofs
