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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_CONSTANTS_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_CONSTANTS_H_

#include <cstdint>

namespace proofs {
namespace ripemd {

// Constants for the RIPEMD-160 hash function from
// RIPEMD-160:
// A Strengthened Version of RIPEMD*
// Hans Dobbertin, Antoon Bosselaers, Bart Preneel
// April 18 1996
//
//   https://homes.esat.kuleuven.be/~bosselae/ripemd160/pdf/AB-9601/AB-9601.pdf

static const uint8_t RL[5][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, /* Round 1: id */
    {7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8}, /* Round 2: rho */
    {3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12}, /* Round 3: rho^2 */
    {1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2}, /* Round 4: rho^3 */
    {4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13}  /* Round 5: rho^4 */
};

/* Right line */
static const uint8_t RR[5][16] = {
    {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12}, /* Round 1: pi */
    {6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1,
     2}, /* Round 2: rho pi */
    {15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4,
     13}, /* Round 3: rho^2 pi */
    {8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10,
     14}, /* Round 4: rho^3 pi */
    {12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9,
     11} /* Round 5: rho^4 pi */
};

static const uint8_t SL[5][16] = {
    {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8}, /* Round 1 */
    {7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12}, /* Round 2 */
    {11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5}, /* Round 3 */
    {11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12}, /* Round 4 */
    {9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6}  /* Round 5 */
};

/* Shifts, right line */
static const uint8_t SR[5][16] = {
    {8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6}, /* Round 1 */
    {9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11}, /* Round 2 */
    {9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5}, /* Round 3 */
    {15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8}, /* Round 4 */
    {8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11}  /* Round 5 */
};

/* Round constants, left line */
static const uint32_t KL[5] = {
    0x00000000u, /* Round 1: 0 */
    0x5A827999u, /* Round 2: floor(2**30 * sqrt(2)) */
    0x6ED9EBA1u, /* Round 3: floor(2**30 * sqrt(3)) */
    0x8F1BBCDCu, /* Round 4: floor(2**30 * sqrt(5)) */
    0xA953FD4Eu  /* Round 5: floor(2**30 * sqrt(7)) */
};

/* Round constants, right line */
static const uint32_t KR[5] = {
    0x50A28BE6u, /* Round 1: floor(2**30 * cubert(2)) */
    0x5C4DD124u, /* Round 2: floor(2**30 * cubert(3)) */
    0x6D703EF3u, /* Round 3: floor(2**30 * cubert(5)) */
    0x7A6D76E9u, /* Round 4: floor(2**30 * cubert(7)) */
    0x00000000u  /* Round 5: 0 */
};

}  // namespace ripemd
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_RIPEMD_RIPEMD_CONSTANTS_H_
