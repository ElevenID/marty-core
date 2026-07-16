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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PK_CIRCUIT_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PK_CIRCUIT_H_

#include <stddef.h>

namespace proofs {

// Verifies that a public key (pkx, pky) is derived from a secret scalar sk
// such that (pkx, pky) = sk * G, where G is the generator of the curve.
template <class LogicCircuit, class Field, class EC>
class Ecpk {
  using EltW = typename LogicCircuit::EltW;
  using Elt = typename LogicCircuit::Elt;
  static constexpr size_t kBits = EC::kBits;

 public:
  struct Witness {
    EltW bits[kBits];
    EltW int_x[kBits];
    EltW int_y[kBits];
    EltW int_z[kBits];

    void input(const LogicCircuit& lc) {
      for (size_t i = 0; i < kBits; ++i) {
        bits[i] = lc.eltw_input();
        if (i < kBits - 1) {
          int_x[i] = lc.eltw_input();
          int_y[i] = lc.eltw_input();
          int_z[i] = lc.eltw_input();
        }
      }
    }
  };

  Ecpk(const LogicCircuit& lc, const EC& ec) : lc_(lc), ec_(ec) {}

  // Verifies that (pkx, pky) = sk * G
  // The witness contains the bits of sk and intermediate points.
  void assert_public_key(EltW pk_x, EltW pk_y, const Witness& w) const {
    EltW zero = lc_.konst(lc_.zero());
    EltW one = lc_.konst(lc_.one());
    EltW gx = lc_.konst(ec_.gx_);
    EltW gy = lc_.konst(ec_.gy_);

    // Initialize at the point at infinity (0, 1, 0)
    EltW ax = zero, ay = one, az = zero;

    // Traverse bits from high to low (standard double-and-add)
    for (size_t i = 0; i < kBits; ++i) {
      typename LogicCircuit::BitW b_bit(w.bits[i], lc_.f_);
      lc_.assert_is_bit(b_bit);

      // Select point to add based on bit: if 1 -> G, if 0 -> Infinity
      // Infinity = (0, 1, 0)
      EltW tx = lc_.mux(b_bit, gx, zero);
      EltW ty = lc_.mux(b_bit, gy, one);
      EltW tz = lc_.mux(b_bit, one, zero);

      // Double the current accumulator
      doubleE(ax, ay, az, ax, ay, az);

      addE(ax, ay, az, ax, ay, az, tx, ty, tz);

      // Check against intermediate witness
      if (i < kBits - 1) {
        // Ensure that the resulting point is equal to the intermediate
        // point provided as input. Performing an explicit equality check
        // ensures that all intermediate witness points are on the curve.
        // This follows by induction. The first (ax,ay,az) is on the curve.
        // The addition formula ensures that the i-th (ax,ay,az) is on the
        // curve; equality ensures that the i-th witness is on the curve.
        lc_.assert_eq(ax, w.int_x[i]);
        lc_.assert_eq(ay, w.int_y[i]);
        lc_.assert_eq(az, w.int_z[i]);

        // Proceed with witnessed values
        ax = w.int_x[i];
        ay = w.int_y[i];
        az = w.int_z[i];
      }
    }

    // Final check: Accumulator should match (pkx, pky).
    // (ax,ay,az) is guaranteed to be on the curve by induction,
    // and the (pkx,pky,1) is a public input that is checked below,
    // and not the point at infinity.
    assert_equal_projective(ax, ay, az, pk_x, pk_y, one);

    // Also verify (pkx, pky) is on curve
    is_on_curve(pk_x, pk_y);
  }

 private:
  // This check is only valid when *both* input points are on the
  // curve or the point at infinity represented as (0,1,0).
  void assert_equal_projective(EltW x1, EltW y1, EltW z1, EltW x2, EltW y2,
                               EltW z2) const {
    // Check projective equality: X1*Z2 == X2*Z1, Y1*Z2 == Y2*Z1
    EltW lhs_x = lc_.mul(x1, z2);
    EltW rhs_x = lc_.mul(x2, z1);
    lc_.assert_eq(lhs_x, rhs_x);

    EltW lhs_y = lc_.mul(y1, z2);
    EltW rhs_y = lc_.mul(y2, z1);
    lc_.assert_eq(lhs_y, rhs_y);
  }
  void is_on_curve(EltW x, EltW y) const {
    // Check that y^2 = x^3 + ax + b
    auto yy = lc_.mul(y, y);
    auto xx = lc_.mul(x, x);
    auto xxx = lc_.mul(x, xx);
    auto ax = lc_.mul(ec_.a_, x);
    auto b = lc_.konst(ec_.b_);
    auto axb = lc_.add(ax, b);
    auto rhs = lc_.add(axb, xxx);
    lc_.assert_eq(yy, rhs);
  }

  void addE(EltW& X3, EltW& Y3, EltW& Z3, EltW X1, EltW Y1, EltW Z1, EltW X2,
            EltW Y2, EltW Z2) const {
    // Copied from VerifyCircuit
    EltW t0 = lc_.mul(X1, X2);
    EltW t1 = lc_.mul(Y1, Y2);
    EltW t2 = lc_.mul(Z1, Z2);
    EltW t3 = lc_.add(X1, Y1);
    EltW t4 = lc_.add(X2, Y2);
    t3 = lc_.mul(t3, t4);
    t4 = lc_.add(t0, t1);
    t3 = lc_.sub(t3, t4);
    t4 = lc_.add(X1, Z1);
    EltW t5 = lc_.add(X2, Z2);
    t4 = lc_.mul(t4, t5);
    t5 = lc_.add(t0, t2);
    t4 = lc_.sub(t4, t5);
    t5 = lc_.add(Y1, Z1);
    EltW X3t = lc_.add(Y2, Z2);
    t5 = lc_.mul(t5, X3t);
    X3t = lc_.add(t1, t2);
    t5 = lc_.sub(t5, X3t);
    auto a = lc_.konst(ec_.a_);
    EltW Z3t = lc_.mul(a, t4);
    auto k3b = lc_.konst(ec_.k3b);
    X3t = lc_.mul(k3b, t2);
    Z3t = lc_.add(X3t, Z3t);
    X3t = lc_.sub(t1, Z3t);
    Z3t = lc_.add(t1, Z3t);
    EltW Y3t = lc_.mul(X3t, Z3t);
    t1 = lc_.add(t0, t0);
    t1 = lc_.add(t1, t0);
    t2 = lc_.mul(a, t2);
    t4 = lc_.mul(k3b, t4);
    t1 = lc_.add(t1, t2);
    t2 = lc_.sub(t0, t2);
    t2 = lc_.mul(a, t2);
    t4 = lc_.add(t4, t2);
    t0 = lc_.mul(t1, t4);
    Y3t = lc_.add(Y3t, t0);
    t0 = lc_.mul(t5, t4);
    X3t = lc_.mul(t3, X3t);
    X3t = lc_.sub(X3t, t0);
    t0 = lc_.mul(t3, t1);
    Z3t = lc_.mul(t5, Z3t);
    Z3t = lc_.add(Z3t, t0);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  void doubleE(EltW& X3, EltW& Y3, EltW& Z3, EltW X, EltW Y, EltW Z) const {
    // Copied from VerifyCircuit
    EltW t0 = lc_.mul(X, X);
    EltW t1 = lc_.mul(Y, Y);
    EltW t2 = lc_.mul(Z, Z);
    EltW t3 = lc_.mul(X, Y);
    t3 = lc_.add(t3, t3);
    EltW Z3t = lc_.mul(X, Z);
    Z3t = lc_.add(Z3t, Z3t);
    auto a = lc_.konst(ec_.a_);
    auto k3b = lc_.konst(ec_.k3b);
    EltW X3t = lc_.mul(a, Z3t);
    EltW Y3t = lc_.mul(k3b, t2);
    Y3t = lc_.add(X3t, Y3t);
    X3t = lc_.sub(t1, Y3t);
    Y3t = lc_.add(t1, Y3t);
    Y3t = lc_.mul(X3t, Y3t);
    X3t = lc_.mul(t3, X3t);
    Z3t = lc_.mul(k3b, Z3t);
    t2 = lc_.mul(a, t2);
    t3 = lc_.sub(t0, t2);
    t3 = lc_.mul(a, t3);
    t3 = lc_.add(t3, Z3t);
    Z3t = lc_.add(t0, t0);
    t0 = lc_.add(Z3t, t0);
    t0 = lc_.add(t0, t2);
    t0 = lc_.mul(t0, t3);
    Y3t = lc_.add(Y3t, t0);
    t2 = lc_.mul(Y, Z);
    t2 = lc_.add(t2, t2);
    t0 = lc_.mul(t2, t3);
    X3t = lc_.sub(X3t, t0);
    Z3t = lc_.mul(t2, t1);
    Z3t = lc_.add(Z3t, Z3t);
    Z3t = lc_.add(Z3t, Z3t);

    X3 = X3t;
    Y3 = Y3t;
    Z3 = Z3t;
  }

  const LogicCircuit& lc_;
  const EC& ec_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PK_CIRCUIT_H_
