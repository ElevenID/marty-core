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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_BITADDR_BITADDR_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_BITADDR_BITADDR_H_

#include <algorithm>
#include <cstddef>

#include "circuits/logic/bit_plucker.h"
#include "circuits/sha/flatsha256_circuit.h"
#include "circuits/tests/ec/pk_circuit.h"
#include "circuits/tests/ripemd/ripemd_circuit.h"
#include "ec/p256k1.h"

namespace proofs {

// BitaddrCircuit verifies that a Bitcoin address corresponds to a known
// private key.
// It checks:
// 1. Public key derivation: (pk_x, pk_y) = sk * G
// 2. Address generation: address = RIPEMD160(SHA256(compressed_pk))
//
// Note: This circuit only handles the legacy version of the Bitcoin address
// format (P2PKH). We can safely ignore the checksum digits of the address
// as those can be publicly verified outside the circuit.
//
// Also note that while Bitcoin addresses are typically presented in Base58Check
// encoding (e.g., starting with '1'), the input to this circuit should be the
// underlying 20-byte hash (Hash160) values.
//
// See
// https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
//
// Example:
// Test case 0 in bitaddr_test.cc uses:
//
// Walkthrough:
// 1. Private Key (Input to Witness):
//    0x9FE33A7A06BD0FE6F5208A61991C49B5B4DD12DC42D9903E789F5118F9675030
//
// 2. Public Key (Compressed):
//    Derived as (pk_x, pk_y) = sk * G
//    Compressed format (used as input to SHA256):
//    0x0252C5262A39751CDDAB2DDF63BA58D04BE30939BE905CF54311385B3C9473E66A
//
// 3. SHA256 Hash:
//    Input: Compressed Public Key (33 bytes)
//    Output: SHA256(0252...66A)
//    0xF7216B404954F08AC191FB7EBA7EB15ADA706687E274707721CAA0DEE454F722
//
// 4. RIPEMD160 Hash (Hash160):
//    Input: SHA256 Output (32 bytes)
//    Output: RIPEMD160(F721...722)
//    0xE30798BD7D0193D12F3F6FEA6D9FF6FEAA2AC721
//
//    *** This RIPEMD160 hash is the "Address" validated by this circuit ***
//    circuit.assert_bitaddr(addr_elt, w) expects addr_elt to be this value.
//
// The following steps are used to generate the full address:
//
// 5. Version Byte (0x00) + Hash160:
//    00E30798BD7D0193D12F3F6FEA6D9FF6FEAA2AC721
//
// 6. Double SHA256 Checksum (first 4 bytes):
//    SHA256(SHA256(00E3...21)) -> ... -> 83090D22
//
// 7. Base58Check Encoding (Final Address):
//    Encode(Version + Hash160 + Checksum)
//    1MhRVNRfTw2NZbKBd1z9yaniy9NJtZVmE1
template <class Logic>
class BitaddrCircuit {
 public:
  using Field = Fp256k1Base;
  using EC = P256k1;  // This application only make sense with the 256k1 curve.
  using EltW = typename Logic::EltW;
  using Elt = typename Field::Elt;
  using v8 = typename Logic::v8;
  using v32 = typename Logic::v32;
  using EcpkWitness = typename Ecpk<Logic, Field, EC>::Witness;
  using ShaCircuit = FlatSHA256Circuit<Logic, BitPlucker<Logic, 2>>;
  using RipemdCircuit = Ripemd160Circuit<Logic, BitPlucker<Logic, 2>>;
  using ShaWitness = typename ShaCircuit::BlockWitness;
  using RipemdWitness = typename RipemdCircuit::BlockWitness;

  static constexpr size_t kBits = EC::kBits;  // 256 for P256K1

  struct Witness {
    EcpkWitness ecpk;
    // SHA256 of 33 bytes fits in 1 block (33 + 9 padding = 42 < 64)
    ShaWitness sha;
    // RIPEMD160 of 32 bytes fits in 1 block (32 + 9 padding = 41 < 64)
    RipemdWitness ripemd;

    EltW pk_x;
    EltW pk_y;
    // Decomposition of pk_x and pk_y
    typename Logic::template bitvec<kBits> pk_x_bits;
    typename Logic::template bitvec<kBits> pk_y_bits;

    void input(const Logic& lc) {
      ecpk.input(lc);
      pk_x = lc.eltw_input();
      pk_y = lc.eltw_input();
      pk_x_bits = lc.template vinput<kBits>();
      pk_y_bits = lc.template vinput<kBits>();
      sha.input(lc);
      ripemd.input(lc);
    }
  };

  // The reason we do this is so that the circuit can have only 1 public
  // argument instead of 160 bits.
  template <size_t N>
  EltW as_scalar_large(const typename Logic::template bitvec<N>& v) const {
    EltW r = lc_.konst(lc_.f_.zero());
    Elt p = lc_.f_.one();
    Elt two = lc_.f_.two();
    for (size_t i = 0; i < N; ++i) {
      EltW vi = lc_.eval(v[i]);
      r = lc_.axpy(r, p, vi);
      p = lc_.f_.mulf(p, two);
    }
    return r;
  }

  explicit BitaddrCircuit(const Logic& lc)
      : lc_(lc), ecpk_(lc, p256k1), sha_(lc), ripemd_(lc) {}

  void assert_bitaddr(EltW addr_elt, const Witness& w) const {
    // 1. Verify (pk_x, pk_y) = sk * G
    ecpk_.assert_public_key(w.pk_x, w.pk_y, w.ecpk);

    // 2. Decompose pk_x and pk_y and verify decomposition
    // Ensure witnesses are bits (implicitly checked by vinput/BitW)
    lc_.assert_eq(w.pk_x, as_scalar_large(w.pk_x_bits));
    lc_.assert_eq(w.pk_y, as_scalar_large(w.pk_y_bits));

    // 3. Serialize pk for SHA256 input
    // Format: [prefix, x_bytes...]
    // prefix is 0x02 if y is even, 0x03 if y is odd.

    // Construct SHA256 input (33 bytes) + Padding
    // Input is 33 bytes.
    // Padding: Append 1 bit (0x80 byte), then zeros, then 64-bit length.
    // Length = 33 * 8 = 264 bits.
    v8 sha_in[64];
    std::fill(sha_in, sha_in + 64, lc_.vbit8(0));

    // Byte 0: prefix
    sha_in[0][0] = w.pk_y_bits[0];
    sha_in[0][1] = lc_.bit(1);
    for (size_t i = 2; i < 8; ++i) sha_in[0][i] = lc_.bit(0);

    // Bytes 1..32: pk_x (Big Endian)
    for (size_t i = 0; i < 32; ++i) {
      size_t byte_idx = 31 - i;
      for (size_t b = 0; b < 8; ++b) {
        sha_in[1 + i][b] = w.pk_x_bits[byte_idx * 8 + b];
      }
    }

    // Byte 33: 0x80
    sha_in[33] = lc_.vbit8(0x80);
    // Bytes 34..55: Zeros (already set by std::fill)

    // Bytes 56..63: Length (Big Endian) = 264
    // Bytes 56..61: Zeros (already set by std::fill)
    sha_in[62] = lc_.vbit8(1);
    sha_in[63] = lc_.vbit8(8);

    // Run SHA256
    v8 nb = lc_.vbit8(1);  // 1 block
    sha_.assert_message(1, nb, sha_in, &w.sha);

    // SHA output is in w.sha.h1 (packed_v32[8]).
    // We need to unpack into v8[32] for RIPEMD.
    // SHA output is Big Endian words.
    // RIPEMD input: 32 bytes.
    // Convert SHA output to bytes.
    v8 ripemd_in[64];
    std::fill(ripemd_in, ripemd_in + 64, lc_.vbit8(0));

    for (size_t i = 0; i < 8; ++i) {
      typename Logic::v32 word = sha_.bp_.unpack_v32(w.sha.h1[i]);
      // v32 word is LSB.
      // Byte 0 (MSB) = word >> 24
      // Byte 3 (LSB) = word & 0xFF
      for (size_t b = 0; b < 8; ++b) {
        ripemd_in[4 * i + 0][b] = word[24 + b];
        ripemd_in[4 * i + 1][b] = word[16 + b];
        ripemd_in[4 * i + 2][b] = word[8 + b];
        ripemd_in[4 * i + 3][b] = word[0 + b];
      }
    }

    // Padding for RIPEMD160
    // Message len = 32 bytes = 256 bits.
    // Byte 32: 0x80
    ripemd_in[32] = lc_.vbit8(0x80);

    // Bytes 56..63: Length (Little Endian for RIPEMD) = 256
    // 256 = 0x0100.
    // 00 01 00 00 00 00 00 00
    ripemd_in[57] = lc_.vbit8(1);

    // Run RIPEMD160
    ripemd_.assert_message(1, nb, ripemd_in, &w.ripemd);

    typename Logic::template bitvec<160> hash_bits;
    size_t bit_idx = 0;

    // Iterate H4 down to H0 to construct the hash value as a little-endian bit
    // sequence corresponding to the big-endian numeric value of the hash. H4's
    // most significant byte (index 3) is the LSB of the numeric value.
    for (int i = 4; i >= 0; --i) {
      v32 word = sha_.bp_.unpack_v32(w.ripemd.h_out[i]);
      for (int b = 3; b >= 0; --b) {
        for (size_t j = 0; j < 8; ++j) {
          hash_bits[bit_idx++] = word[b * 8 + j];
        }
      }
    }

    EltW hash_val = as_scalar_large(hash_bits);

    lc_.assert_eq(addr_elt, hash_val);
  }

 private:
  const Logic& lc_;
  Ecpk<Logic, Field, EC> ecpk_;
  ShaCircuit sha_;
  RipemdCircuit ripemd_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_PQ_BITADDR_BITADDR_H_
