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

#include "random/transcript.h"

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "algebra/fp.h"
#include "algebra/static_string.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
typedef Fp<4> Field;
static const Field F(
    "11579208921035624876269744694940757353008614341529031419553363130886709785"
    "3951");
typedef Field::Elt Elt;

TEST(Transcript, Write) {
  uint8_t buf1[4], buf2[4];

  Transcript ts1((uint8_t*)"test", 4);
  ts1.write(F.of_scalar(7), F);
  ts1.bytes(buf1, 4);

  Transcript ts2((uint8_t*)"test", 4);
  ts2.write(F.of_scalar(8), F);
  ts2.bytes(buf2, 4);

  EXPECT_NE(buf1, buf2);
}

TEST(Transcript, TwoBlocks) {
  // Generate two blocks and check that they are not the same.
  // Hardcoded 16 assumes AES PRF
  uint8_t a[16], b[16];
  Transcript ts((uint8_t*)"test", 4);
  ts.write(F.of_scalar(8), F);
  ts.bytes(a, 16);
  ts.bytes(b, 16);
  bool same = true;
  for (size_t i = 0; i < 16; ++i) {
    same &= (a[i] == b[i]);
  }
  EXPECT_FALSE(same);
}

TEST(Transcript, Associative) {
  constexpr size_t n = 100;
  uint8_t a[n], b[n];
  for (size_t i = 0; i < n; ++i) {
    Transcript ts((uint8_t*)"test", 4);
    ts.write(F.of_scalar(7), F);
    {
      Transcript ts1 = ts.clone();
      ts.bytes(a, i);
      ts.bytes(a + i, n - i);
    }
    {
      Transcript ts1 = ts.clone();
      ts1.bytes(b, n);
    }
    for (size_t j = 0; j < n; ++j) {
      EXPECT_EQ(a[i], b[i]);
    }
  }
}

void dump_elt(Elt elt) {
  uint8_t buf[Field::kBytes];
  F.to_bytes_field(buf, elt);
  for (size_t i = Field::kBytes; i-- > 0;) {
    printf("%02x", buf[i]);
  }
  printf(",\n");
}

void check_elt_output(Transcript& ts, const StaticString want[/*16*/]) {
  Elt e[16];
  ts.clone().elt(e, 16, F);

  for (size_t i = 0; i < 16; ++i) {
    // Generating challenge one element at a time is equivalent to generating
    // multiple elements together.
    EXPECT_EQ(ts.elt(F), e[i]);
    // EXPECT_EQ(F.of_string(want[i]), e[i]);
    dump_elt(e[i]);
  }
}

void check_nat_output(Transcript& ts, const size_t want[/* 24 */]) {
  size_t nat_sizes[24] = {
      1, 1, 1, 2, 2, 2,  7,    7,    7,     7,     32,     32,     32,    32,
      256, 256, 256, 256, 1000, 10000, 60000, 65535, 100000, 100000};
  for (size_t i = 0; i < 24; ++i) {
    size_t got = ts.nat(nat_sizes[i]);
    printf("%zu ", got);
    // EXPECT_EQ(got, want[i]);
  }
  printf("\n");
}

void check_choose_output(Transcript& ts, const size_t want[]) {
  size_t nat_sizes[6] = {31, 32, 63, 64, 1000, 65535};
  size_t got[20];

  for (size_t i = 0; i < 6; ++i) {
    ts.choose(got, nat_sizes[i], 20);
    for (size_t j = 0; j < 20; ++j) {
      EXPECT_EQ(got[j], want[i * 20 + j]);
    }
  }
}

TEST(Transcript, TestVectors) {
  Transcript ts((uint8_t*)"test", 4, 4);
  // write a byte array
  uint8_t d[100];
  for (size_t i = 0; i < 100; ++i) {
    d[i] = static_cast<uint8_t>(i);
  }
  ts.write(d, 100);

  StaticString want[16] = {
      StaticString(
          "0x8b297f0bffd583c6c6b6796385d5fd20a08665733b833970ebdd1054bbbc1b14"),
      StaticString(
          "0x0667c08ad7f38efec5f30dc8aa4f20d749cdcf96d63a770f9810ac5c0ca8dcb1"),
      StaticString(
          "0xc8037fc12d4da00b5dc7597e3042f33f72a06f970cb71fb6b103ebb5419d8a6b"),
      StaticString(
          "0xfbbcfa1eac48728fbfdacc1c21e2f78119457e0846337e46140e38e62856c4c5"),
      StaticString(
          "0x5358ae603691cc759faeb572fb6642654ea1c3dbc8f81d00276dd8c4df95aa58"),
      StaticString(
          "0x5266158c3c895dede5a23b6ce85a9f564b8059ebfcd1741f54497ec58189873e"),
      StaticString(
          "0x3ecea4b2343c007fc32f2aff40dc7320945f101ecae5d52494db21ad326e9739"),
      StaticString(
          "0x6462dd575e6b874118607212feec7ce5417ae3bf0f2e86604596f35d48bbaea2"),
      StaticString(
          "0x6d56c703c369edea3595db6b958241580ae9b4a76fead961413ed9e9e5852dcd"),
      StaticString(
          "0x6d31073cee650212a71b7b13e9f951e00ef3b14a008a79dd95047b26a4a83d06"),
      StaticString(
          "0x1b9e2a6666da63c43e52227d91a8a7f0bd5311f63c2e3a18839133375639e6cb"),
      StaticString(
          "0x332ea49dd23dd4745631ecbb15696192b1fa127256baf7a0483fd27db6f09a48"),
      StaticString(
          "0x43e735927ccbdc4d5ce912675d638d6d3dc8eef3def34504304e938846f157d6"),
      StaticString(
          "0xdc4a8868ae75e733a7257a8589230392a98d78594836dfccd01304742b5b3ad5"),
      StaticString(
          "0x976353931711c634f2691e507b119fd7f6e653d419a2620676122db08db18765"),
      StaticString(
          "0x332729ab436dca654866a9382deaee0add6fb7e90a80261f1488e56598e8bc99"),
  };

  check_elt_output(ts, want);

  // write a field element
  ts.write(F.of_scalar(7), F);
  StaticString want2[16] = {
      StaticString(
          "0x609db3e9a8f548df038519fa46cef23eb8c6553d3c1f698604e60a51613a738e"),
      StaticString(
          "0x1cb69cb31999eb88e83c7586aac53f5e3286b084b0cf9e43619b48df01e0a310"),
      StaticString(
          "0x3bf36e3ddc690a1b12b417628c115959b373d056c90c42dc2417baf46f538868"),
      StaticString(
          "0xe336594f29dcda52e48896517b5cdb2d062ffd861ab02db5f8ca197aacc635f6"),
      StaticString(
          "0xc1f396a8bad16bb0f57da6d380402a25b571bd4691226d11449a741440e325c8"),
      StaticString(
          "0x5195336ec73751de066e3a8939b40c3c5555f1a513486dfc50dcf4c2d47e6ff2"),
      StaticString(
          "0x8dcf872f3ded2b7ed1d1ee9a2b125bedc6eacd3c09b3a4a5286d8fc2fc3a6634"),
      StaticString(
          "0x950dd2ef7be25eab686a6688497962ee4ad521da12b9ff3d8e56ad9435885b12"),
      StaticString(
          "0xe14389d1d8448678cac33fdbc9aab20dba019e75149d170dd2f353891cd4b84f"),
      StaticString(
          "0xe84906c09cd6423865baf64e48027cc598d52bdb90b17524c87ea892e53b5200"),
      StaticString(
          "0x493cea587f1ec5622c04221cd6e5a41c26c1c1c24c0375f7aaa367d9678d83bc"),
      StaticString(
          "0x5aca0010aced30bcb3b84a7f10ea39c4269ab7c92fcb6cff52958d8921ef2cc5"),
      StaticString(
          "0x4498fa8340f41467c0fa813bd0ca83ef6e1c4b85c7b1168a94339fd9e8296139"),
      StaticString(
          "0xf9a95b738a8e775421b1baa503abbeed2d283b236ebba25e1954b3c993d30a3d"),
      StaticString(
          "0x98178711d03a0b1204ebb56b37bd3a2724dfb08e4dc925609391768b126d21f2"),
      StaticString(
          "0x79251f49534f5c4b10b798b2dbf6e80a3b07593f616ce6a9617ccc61040aac78"),
  };

  check_elt_output(ts, want2);

  // write a field element array
  Elt array[2] = {F.of_scalar(8), F.of_scalar(9)};
  ts.write(array, 1, 2, F);

  StaticString want3[16] = {
      StaticString(
          "0xae1a921288590205fc24543303ff527476359b8db4a983b2886a133b02f3217e"),
      StaticString(
          "0x8c5d52a04b295f9fdb45ab66100fa00ca32c9634aa87cbbdb2bc3e1912459feb"),
      StaticString(
          "0x12f82963b5b242156f6e9eb756eddee7652b60c7d6394403f7bd995e0b9bcd9c"),
      StaticString(
          "0x880aa50b049b3939055deb7933749d338bb3fb5f64a9adf95019e6cfc232995c"),
      StaticString(
          "0xf8558f693f0fa6df20a37147a898fb4c678831f566d80113bbe2cdcd18285da2"),
      StaticString(
          "0xbbcc8d9b46f88bc8c6cec0ad2d5e49508b7db91d548548eddc61800de1329e1c"),
      StaticString(
          "0x479a17244398caae8155a73438a22583df7de10a8a2e12ad53ddd3bc7305fac9"),
      StaticString(
          "0x9ba1917f1227932250288a843f64b4e7b7f47a5fbc16c111f6e1f76235ccf38c"),
      StaticString(
          "0xd1582138045d1636fb7f677c9e8a4a4143ce2b2bb54fb4f49fb0ad1fee5df6b4"),
      StaticString(
          "0x05331e5b8508f79c017a8dfbbb805f3f8c5e3e4bc417e44849b9212439646331"),
      StaticString(
          "0xb6b95862194ca52dcaa9ee651b7fc5b708f43feae108bb9a7f95213f4d069048"),
      StaticString(
          "0xe86b1602f0a54c4e237867ebaf05e7581464fd238e50f6ed9c3cea63909c8e60"),
      StaticString(
          "0xb7280439f3b21b113ff29cefe39292d5e2d137709c3d3cec36473a0f97a24e62"),
      StaticString(
          "0xbeaa5e08257d232506fb3e46c6daa29e0859c34c7d0cd673bc6706ee261ae059"),
      StaticString(
          "0x0691ead55728cd087a1952b22b6628ba4e26fbefc8debeec5e6fbc3a16f637be"),
      StaticString(
          "0x47dc31f6d8bc9c44290781176df3e4b95ac8793a4a42fa5859c564d92d6d5af5"),
  };
  check_elt_output(ts, want3);

  ts.write((uint8_t*)"nats", 4);

  size_t want_nat[] = {0, 0,  0,   0,    0,     0,     3,     0,
                       4, 5,  10,  30,   27,    22,    100,   189,
                       3, 92, 999, 3105, 40886, 51590, 56367, 10678};
  check_nat_output(ts, want_nat);

  ts.write((uint8_t*)"choose", 6);

  size_t want_ch[] = {
      /* 31 */
      10, 29, 30, 11, 4, 15, 16, 28, 19, 21, 25, 18, 17, 3, 5, 23, 24, 22, 6, 1,
      /* 32 */
      3, 17, 18, 8, 30, 7, 14, 19, 25, 23, 12, 4, 31, 16, 0, 6, 20, 27, 11, 10,
      /* 63 */
      9, 56, 61, 45, 35, 53, 51, 3, 39, 32, 31, 6, 59, 58, 54, 22, 27, 62, 55,
      19,
      /* 64 */
      12, 52, 39, 17, 51, 38, 58, 2, 28, 27, 46, 63, 61, 50, 40, 55, 47, 13, 56,
      32,
      /* 1000 */
      157, 668, 572, 138, 913, 994, 797, 249, 440, 723, 489, 241, 383, 108, 710,
      341, 406, 585, 42, 692,
      /* 65535 */
      40745, 48408, 17108, 44500, 53993, 10008, 24910, 52200, 61265, 54989,
      41237, 25958, 28697, 61187, 34729, 3525, 9005, 38627, 9724, 12169};
  check_choose_output(ts, want_ch);
}

TEST(Transcript, TestVec) {
  uint8_t key[32];

  Transcript ts((uint8_t*)"test", 4);
  uint8_t d[100];
  for (size_t i = 0; i < 100; ++i) {
    d[i] = static_cast<uint8_t>(i);
  }
  ts.write(d, 100);
  ts.get(key);

  // manually computed SHA256 of
  //    0
  //    4 0 0 0 0 0 0 0
  //    t e s t
  //    0                   // TAG
  //    100 0 0 0 0 0 0 0   // LENGTH
  //    0 1 2 ...           // PAYLOAD
  {
    const uint8_t key1[32] = {0x60, 0xcd, 0x16, 0x34, 0x92, 0x0f, 0x1c, 0xf2,
                              0xae, 0x83, 0x15, 0x02, 0xbf, 0x4b, 0xb9, 0x3a,
                              0x60, 0xcd, 0x03, 0xee, 0xb1, 0x9f, 0x93, 0xe2,
                              0xd6, 0xd5, 0x0d, 0xbd, 0x09, 0x84, 0xcb, 0xd8};
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(key[i], key1[i]);
    }
  }

  {
    // obtain two AES blocks
    uint8_t bytes[32];
    ts.bytes(bytes, 32);

    // manually computed AES256 of [0 0 0 0 0 0 0 0] and
    /// [1 0 0 0 0 0 0 0] under KEY
    const uint8_t bytes1[32] = {0x14, 0x1B, 0xBC, 0xBB, 0x54, 0x10, 0xDD, 0xEB,
                                0x70, 0x39, 0x83, 0x3B, 0x73, 0x65, 0x86, 0xA0,
                                0x20, 0xFD, 0xD5, 0x85, 0x63, 0x79, 0xB6, 0xC6,
                                0xC6, 0x83, 0xD5, 0xFF, 0x0B, 0x7F, 0x29, 0x8B};
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(bytes[i], bytes1[i]);
    }
  }

  // append another zero
  ts.write(d, 1);
  ts.get(key);

  {
    const uint8_t key1[32] = {0x18, 0x19, 0x78, 0x38, 0x0b, 0x6f, 0xf3, 0x21,
                              0x85, 0xc8, 0x28, 0xd9, 0xa0, 0x07, 0xee, 0x93,
                              0x0b, 0xce, 0x2e, 0x94, 0x7f, 0x88, 0x7f, 0x85,
                              0xb6, 0x4f, 0x39, 0x9a, 0x94, 0xcb, 0xe4, 0xa8};
    for (size_t i = 0; i < 32; ++i) {
      EXPECT_EQ(key[i], key1[i]);
    }
  }
}
}  // namespace
}  // namespace proofs
