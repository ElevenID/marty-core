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

#ifndef PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_IO_H_
#define PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_IO_H_

#include <cstddef>

#include "circuits/mdoc/mdoc_constants.h"

namespace proofs {

static constexpr size_t kMdoc1DateLen = 20;  // Length of CBOR-formatted time.
static constexpr size_t kMdoc1MaxSHABlocks = 7;
static constexpr size_t kMdoc1CborIndexBits = 9;
static constexpr size_t kMdoc1MaxMsoLen =
    kMdoc1MaxSHABlocks * 64 - 9 - kCose1PrefixLen;
static constexpr size_t kMdoc1SHAPluckerBits = 3;
}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_CIRCUITS_TESTS_MDOC_MDOC_1F_IO_H_
