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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_CBOR_PLUCK_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_CBOR_PLUCK_H_
#include <stddef.h>
#include <stdint.h>

#include <vector>

#include "algebra/interpolation.h"
#include "algebra/poly.h"
#include "circuits/logic/bit_plucker_constants.h"
#include "circuits/logic/polynomial.h"

namespace proofs {
// Special plucker that decodes into a pair (B, J) where B is one bit,
// and J is an array of NJ bits at most one of which can be set.
//
// B can assume one of two distinct values, and J can assume NJ+1
// distinct values.  Thus there are N = 2*(NJ+1) evaluation points.
// We encode J as the index IJ of which bit is set, or IJ=NJ if no bit
// is set.
template <class Logic, size_t NJ>
class CborPlucker {
 public:
  using Field = typename Logic::Field;
  using BitW = typename Logic::BitW;
  using EltW = typename Logic::EltW;
  using Elt = typename Field::Elt;
  static constexpr size_t kN = 2 * (NJ + 1);
  using PolyN = Poly<kN, Field>;
  using InterpolationN = Interpolation<kN, Field>;
  const Logic& l_;
  PolyN pluckerb_;
  std::vector<PolyN> pluckerj_;

  explicit CborPlucker(const Logic& l) : l_(l), pluckerj_(NJ) {
    const Field& F = l_.f_;  // shorthand
    // evaluation points
    PolyN X;
    for (size_t i = 0; i < kN; ++i) {
      X[i] = bit_plucker_point<Field, kN>()(i, F);
    }

    // encode B in the low-order bit
    PolyN Y;
    for (size_t i = 0; i < kN; ++i) {
      Y[i] = F.of_scalar(i & 1);
    }
    pluckerb_ = InterpolationN::monomial_of_lagrange(Y, X, F);

    // encode J in the high-order bits
    for (size_t j = 0; j < NJ; ++j) {
      for (size_t i = 0; i < kN; ++i) {
        Y[i] = F.of_scalar((i >> 1) == j);
      }
      pluckerj_[j] = InterpolationN::monomial_of_lagrange(Y, X, F);
    }
  }

  BitW pluckb(const EltW& e) const {
    const Logic& L = l_;  // shorthand
    const Polynomial<Logic> P(L);

    EltW v = P.eval(pluckerb_, e);
    L.assert_is_bit(v);
    return BitW(v, L.f_);
  }

  typename Logic::template bitvec<NJ> pluckj(const EltW& e) const {
    typename Logic::template bitvec<NJ> r;
    const Logic& L = l_;  // shorthand
    const Polynomial<Logic> P(L);

    for (size_t j = 0; j < NJ; ++j) {
      EltW v = P.eval(pluckerj_[j], e);
      L.assert_is_bit(v);
      r[j] = BitW(v, L.f_);
    }

    return r;
  }
};

template <class Field, size_t NJ>
struct cbor_plucker_point {
  using Elt = typename Field::Elt;
  static constexpr size_t kN = 2 * (NJ + 1);

  // packing of bits compatible with even_lagrange_basis():
  Elt operator()(bool b, size_t j, const Field& F) const {
    uint64_t bits = b + 2 * j;
    return bit_plucker_point<Field, kN>()(bits, F);
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_CBOR_PARSER_CBOR_PLUCK_H_
