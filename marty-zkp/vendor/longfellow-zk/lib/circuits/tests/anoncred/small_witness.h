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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_ANONCRED_SMALL_WITNESS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_ANONCRED_SMALL_WITNESS_H_

#include <stddef.h>
#include <string.h>

#include <cstdint>
#include <vector>

#include "algebra/static_string.h"
#include "arrays/dense.h"
#include "circuits/ecdsa/verify_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/mdoc/mdoc_witness.h"
#include "circuits/sha/flatsha256_witness.h"
#include "circuits/tests/anoncred/small_io.h"

namespace proofs {

class SmallOpenedAttribute {
 public:
  size_t ind_, len_;
  std::vector<uint8_t> value_;
  SmallOpenedAttribute(size_t ind, size_t len, const uint8_t* val, size_t vlen)
      : ind_(ind), len_(len), value_(val, val + vlen) {}
};

template <typename EC, typename Field, class ScalarField>
class SmallWitness {
  using ECField = typename EC::Field;
  using ECElt = typename ECField::Elt;
  using ECNat = typename ECField::N;
  using Elt = typename Field::Elt;
  using Nat = typename Field::N;
  using EcdsaWitness = VerifyWitness3<EC, ScalarField>;
  static constexpr size_t kMaxSHABlocks = 7;

 public:
  const EC ec_;
  Elt e_, e2_;      /* Issuer signature values. */
  Elt dpkx_, dpky_; /* device key */
  EcdsaWitness ew_, dkw_;
  uint8_t now_[kDateLen]; /* CBOR-formatted time used for expiry comparison. */

  FlatSHA256Witness::BlockWitness bw_[kMaxSHABlocks];
  uint8_t signed_bytes_[kMaxSHABlocks * 64];
  uint8_t numb_; /* Number of the correct sha block. */

  explicit SmallWitness(const EC& ec, const ScalarField& Fn)
      : ec_(ec), ew_(Fn, ec), dkw_(Fn, ec) {}

  void fill_sha(DenseFiller<Field>& filler,
                const FlatSHA256Witness::BlockWitness& bw) const {
    BitPluckerEncoder<Field, 3> BPENC(ec_.f_);
    for (size_t k = 0; k < 48; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.outw[k]));
    }
    for (size_t k = 0; k < 64; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.oute[k]));
      filler.push_back(BPENC.mkpacked_v32(bw.outa[k]));
    }
    for (size_t k = 0; k < 8; ++k) {
      filler.push_back(BPENC.mkpacked_v32(bw.h1[k]));
    }
  }

  void fill_witness(DenseFiller<Field>& filler, bool small = false) const {
    filler.push_back(e_);
    filler.push_back(dpkx_);
    filler.push_back(dpky_);

    ew_.fill_witness(filler);
    dkw_.fill_witness(filler);

    filler.push_back(numb_, 8, ec_.f_);
    for (size_t i = 0; i < kMaxSHABlocks * 64; ++i) {
      filler.push_back(signed_bytes_[i], 8, ec_.f_);
    }
    for (size_t j = 0; j < kMaxSHABlocks; j++) {
      fill_sha(filler, bw_[j]);
    }
  }

  bool compute_witness(Elt pkX, Elt pkY, const uint8_t mdoc[/* len */],
                       size_t len, const uint8_t transcript[/* tlen */],
                       size_t tlen, const uint8_t tnow[/*kDateLen*/],
                       const StaticString& r, const StaticString& s,
                       const StaticString& dr, const StaticString& ds) {
    Nat ne = nat_from_hash<Nat>(mdoc, len);
    e_ = ec_.f_.to_montgomery(ne);

    // Parse (r,s).
    Nat nr = Nat(r);
    Nat ns = Nat(s);
    ew_.compute_witness(pkX, pkY, ne, nr, ns);

    Nat ne2 = nat_from_hash<Nat>(transcript, tlen);
    Nat nr2 = Nat(dr);
    Nat ns2 = Nat(ds);

    dpkx_ = ec_.f_.to_montgomery(nat_from_be<Nat>(&mdoc[100]));
    dpky_ = ec_.f_.to_montgomery(nat_from_be<Nat>(&mdoc[132]));
    e2_ = ec_.f_.to_montgomery(ne2);
    dkw_.compute_witness(dpkx_, dpky_, ne2, nr2, ns2);

    FlatSHA256Witness::transform_and_witness_message(len, mdoc, kMaxSHABlocks,
                                                     numb_, signed_bytes_, bw_);

    memcpy(now_, tnow, kDateLen);
    return true;
  }
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_ANONCRED_SMALL_WITNESS_H_
