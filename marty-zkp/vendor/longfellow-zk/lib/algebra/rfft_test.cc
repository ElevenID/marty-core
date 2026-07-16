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


#include "algebra/rfft.h"

#include <stddef.h>

#include <cstdint>
#include <vector>

#include "algebra/fft.h"
#include "algebra/fp2.h"
#include "algebra/fp_p256.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
TEST(RFFTTest, Simple) {
  using BaseField = Fp256<>;
  using BaseElt = BaseField::Elt;
  using ExtField = Fp2<BaseField>;
  using ExtElt = ExtField::Elt;

  const BaseField F0;        // base field
  const ExtField F_ext(F0);  // p^2 field extension

  ExtElt omega0 = F_ext.of_string(
      "112649224146410281873500457609690258373018840430489408729223714171582664"
      "680802",
      "840879943585409076957404614278186605601821689971823787493130182544504602"
      "12908");
  uint64_t omega_order = 1ull << 31;

  // Try various roots of unity while maintaining the invariant that
  // omega^{n/4} = I.  The goal of this exercise is to make sure that
  // the rfft does not depend on a specific 8-th root of unity.
  //
  // The actual root of unity used in the FFT is (omega^r) for r =
  // omega_order / n, and omega^{r*n/4} = I (as opposed to -I) holds.
  // Thus (omega^{1+4*j})^{r*n/4} = I also holds for all j, but the
  // 8-th roots are different.  Since there are only two eight roots
  // of unity under the constraint, two iterations are sufficient.
  //
  ExtElt omega = omega0;
  for (size_t iter = 0; iter < 2; ++iter) {
    ExtElt one = F_ext.mulf(omega, F_ext.conjf(omega));
    EXPECT_EQ(one, F_ext.one());

    for (size_t n = 1; n < 1024; n *= 2) {
      std::vector<BaseElt> AR0(n);
      std::vector<BaseElt> AR1(n);
      std::vector<ExtElt> AC(n);

      // Arbitrary coefficients in base field.  Keep three copies.
      for (size_t i = 0; i < n; ++i) {
        AR0[i] = F0.of_scalar(i * i * i + (i & 0xF) + (i ^ (i << 2)));
        AR1[i] = AR0[i];
        AC[i] = ExtElt{AR0[i]};
      }

      // compare RFFT against FFT
      FFT<ExtField>::fftb(&AC[0], n, omega, omega_order, F_ext);
      RFFT<ExtField>::r2hc(&AR0[0], n, omega, omega_order, F_ext);

      for (size_t i = 0; i < n; ++i) {
        if (i + i <= n) {
          EXPECT_EQ(AR0[i], AC[i].re);
        } else {
          EXPECT_EQ(AR0[i], AC[i].im);
        }
      }

      // invert and compare against AR1
      RFFT<ExtField>::hc2r(&AR0[0], n, omega, omega_order, F_ext);
      BaseElt scale = F0.of_scalar(n);
      for (size_t i = 0; i < n; ++i) {
        EXPECT_EQ(AR0[i], F0.mulf(scale, AR1[i]));
      }
    }

    // advance root of unity
    F_ext.mul(omega, omega0);
    F_ext.mul(omega, omega0);
    F_ext.mul(omega, omega0);
    F_ext.mul(omega, omega0);
  }
}

}  // namespace
}  // namespace proofs
