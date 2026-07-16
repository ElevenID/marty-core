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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PK_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PK_WITNESS_H_

#include <cstddef>

#include "arrays/dense.h"

namespace proofs {

template <class EC, class ScalarField>
class PkWitness {
  using Field = typename EC::Field;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;

 public:
  constexpr static size_t kBits = EC::kBits;
  const ScalarField& fn_;
  const EC& ec_;

  // Witness components
  Elt bits_[kBits];
  Elt int_x_[kBits];
  Elt int_y_[kBits];
  Elt int_z_[kBits];

  PkWitness(const ScalarField& Fn, const EC& ec) : fn_(Fn), ec_(ec) {}

  void fill_witness(DenseFiller<Field>& filler) const {
    for (size_t i = 0; i < kBits; ++i) {
      filler.push_back(bits_[i]);
      if (i < kBits - 1) {
        filler.push_back(int_x_[i]);
        filler.push_back(int_y_[i]);
        filler.push_back(int_z_[i]);
      }
    }
  }

  // Computes witness for PK = sk * G
  bool compute_witness(const Nat sk) {
    const Field& F = ec_.f_;
    const Elt one = F.one();
    const Elt bgX = ec_.gx_;
    const Elt bgY = ec_.gy_;

    Elt aX = F.zero();
    Elt aY = one;
    Elt aZ = F.zero();

    // VerifyCircuit loops i from 0 to kBits-1.
    // So bits_[0] corresponds to sk.bit(kBits - 1).

    for (size_t i = 0; i < kBits; ++i) {
      // Get bit from high to low
      size_t bit_idx = kBits - 1 - i;
      int bit = sk.bit(bit_idx);
      bits_[i] = F.of_scalar(bit);

      ec_.doubleE(aX, aY, aZ, aX, aY, aZ);

      if (bit == 1) {
        ec_.addE(aX, aY, aZ, aX, aY, aZ, bgX, bgY, one);
      } else {
        // Adding point at infinity (0, 1, 0)
        ec_.addE(aX, aY, aZ, aX, aY, aZ, F.zero(), one, F.zero());
      }

      int_x_[i] = aX;
      int_y_[i] = aY;
      int_z_[i] = aZ;
    }

    // Sanity check: result shouldn't be infinity if sk != 0 (assuming order is
    // prime and sk < order)
    if (aZ == F.zero() && sk != Nat(0)) {
      // Technically sk=0 gives point at infinity.
      // If sk != 0, aZ should be non-zero (unless P is point of order 2 etc,
      // but this is a cryptographic curve).
      return false;
    }
    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_EC_PK_WITNESS_H_
