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

#ifndef PRIVACY_PROOFS_ZK_LIB_RANDOM_RANDOM_H_
#define PRIVACY_PROOFS_ZK_LIB_RANDOM_RANDOM_H_

#include <array>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <utility>
#include <vector>

#include "util/panic.h"
#include "util/secure_wipe.h"

namespace proofs {

// Our protocols require random coins; this interface provides both prover
// and verifier components with those coins. Re-implementing this interface
// allows easily supporting the Fiat-Shamir transform, or for sampling using
// a system provided RNG such as openssl.
class RandomEngine {
 public:
  virtual ~RandomEngine() = default;
  virtual void bytes(uint8_t* buf, size_t n) = 0;  // pure virtual

  // Sample a random field element.
  template <class Field>
  typename Field::Elt elt(const Field& F) {
    return F.sample([this](size_t n, uint8_t* buf) { bytes(buf, n); });
  }

  template <class Field>
  typename Field::Elt subfield_elt(const Field& F) {
    return F.sample_subfield([this](size_t n, uint8_t* buf) {
      bytes(buf, n);
    });
  }

  // Convenience method to sample an array of random field elements.
  template <class Field>
  void elt(typename Field::Elt e[/*n*/], size_t n, const Field& F) {
    for (size_t i = 0; i < n; ++i) e[i] = elt(F);
  }

  // random size_t < n
  size_t nat(size_t n) {
    std::array<uint8_t, sizeof(size_t)> buf{};
    size_t candidate = 0;
    return nat_with_scratch(n, buf, candidate);
  }

  // Scratch-aware rejection-sampling seam used to verify cleanup on success
  // and exceptions. Normal callers should use nat.
  size_t nat_with_scratch(size_t n,
                          std::array<uint8_t, sizeof(size_t)>& buf,
                          size_t& candidate) {
    SecureObjectWipeGuard<std::array<uint8_t, sizeof(size_t)>> wipe_buf(buf);
    SecureObjectWipeGuard<size_t> wipe_candidate(candidate);
    check(n > 0, "nat(0)");

    // compute the minimum number of random bytes needed
    size_t l = 0;
    size_t nn = n;
    while (nn != 0) {
      nn >>= 8;
      ++l;
    }
    check(l <= sizeof(size_t), "l <= sizeof(size_t)");

    size_t msk = mask(n);
    // rejection sampling
    do {
      secure_wipe_object(buf);
      secure_wipe_object(candidate);
      // consume L random bytes
      bytes(buf.data(), l);

      // little-endian read
      for (size_t i = l; i-- > 0;) {
        candidate = (candidate << 8) | buf[i];
      }

      // mask off high bits
      candidate &= msk;
    } while (candidate >= n);

    return candidate;
  }

  // Choose K distinct random naturals in [0..N).
  // Textbook algorithm requiring O(N) space
  void choose(size_t res[/*k*/], size_t n, size_t k) {
    check(n >= k, "n >= k");

    std::vector<size_t> A(n);
    for (size_t i = 0; i < n; ++i) {
      A[i] = i;
    }
    for (size_t i = 0; i < k; ++i) {
      size_t j = i + nat(n - i);
      std::swap(A[i], A[j]);
      res[i] = A[i];
    }
  }

  // the minimal bitmask such that (n & mask) == n
  size_t mask(size_t n) {
    size_t mask = 0;
    while ((n & mask) != n) {
      mask <<= 1;
      mask |= 1u;
    }
    return mask;
  }
};
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_RANDOM_RANDOM_H_
