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

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "arrays/dense.h"
#include "cbor/host_decoder.h"
#include "circuits/cbor_parser/cbor.h"
#include "circuits/cbor_parser/cbor_constants.h"
#include "circuits/cbor_parser/cbor_testing.h"
#include "circuits/cbor_parser/cbor_witness.h"
#include "circuits/compiler/circuit_dump.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/counter.h"
#include "circuits/logic/evaluation_backend.h"
#include "circuits/logic/logic.h"
#include "gf2k/gf2_128.h"
#include "sumcheck/circuit.h"
#include "sumcheck/testing.h"
#include "util/log.h"
#include "gtest/gtest.h"

namespace proofs {
namespace {
using Field = GF2_128<>;
const Field F;

using CborWitness = CborWitness<Field>;
using CborTesting = CborTesting<Field>;

using CompilerBackend = CompilerBackend<Field>;
using LogicCircuit = Logic<Field, CompilerBackend>;

using EvalBackend = EvaluationBackend<Field>;
using Logic = Logic<Field, EvalBackend>;

/*
    Decoding of the example:

A6                                      # map(6)
   67                                   # text(7)
      76657273696F6E                    # "version"
   63                                   # text(3)
      312E30                            # "1.0"
   6F                                   # text(15)
      646967657374416C676F726974686D    # "digestAlgorithm"
   67                                   # text(7)
      5348412D323536                    # "SHA-256"
   67                                   # text(7)
      646F6354797065                    # "docType"
   75                                   # text(21)
      6F72672E69736F2E31383031332E352E312E6D444C # "org.iso.18013.5.1.mDL"
   6C                                   # text(12)
      76616C756544696765737473          # "valueDigests"
   A2                                   # map(2)
      71                                # text(17)
         6F72672E69736F2E31383031332E352E31 # "org.iso.18013.5.1"
      AF                                # map(15)
         0D                             # unsigned(13)
         58 20                          # bytes(32)
            B62897FBDA2139614087A73D0CE63A16A0BE43225AC05F6BE3DD777FF5D569D2
         0B                             # unsigned(11)
         58 20                          # bytes(32)
            6F9484C89B938644A48E14A5791F1C2A3B83BA52BFB6CA0D9A3A8FD844F35BD4
         04                             # unsigned(4)
         58 20                          # bytes(32)
            43CD174E9885F2F1F32DF4742F4F662EB18A9DCB82624B3165512E1EA241E1AC
         07                             # unsigned(7)
         58 20                          # bytes(32)
            7EA194A8B5C9CA0BEC5C2E979D9D8EFA2FE7C4CFA88713ED50F967912724CB57
         11                             # unsigned(17)
         58 20                          # bytes(32)
            BBCE5F310089FEADB8B7A2C239BC3E6FA97ED101C8287FF48A4BDFF6CA37BED2
         10                             # unsigned(16)
         58 20                          # bytes(32)
            D2BDE38E57AAB48F343CF5DE25540D9E2324368C1D135A68FD0C0F7843CCB5DD
         01                             # unsigned(1)
         58 20                          # bytes(32)
            732CAA70D74933D90832C1679D006C4807486276AC9C86B9C183257C7F1B23C5
         12                             # unsigned(18)
         58 20                          # bytes(32)
            593EBAA6A07F2770B2D603910F3677FF7B0AE9B6BE4A9DD860644977D726EDA8
         06                             # unsigned(6)
         58 20                          # bytes(32)
            21DC5AD5BA5B1A34C338EC87FDA6910B59D45276906C804DB13953AF0C75E5D1
         02                             # unsigned(2)
         58 20                          # bytes(32)
            2F445344E4865E847B39FC15B285A5EB40CC38B99D6CD4B4613EC6A3E9336148
         00                             # unsigned(0)
         58 20                          # bytes(32)
            347BCC0AB488F37F020F660DAC4471233A9445AAD908BE3ADAC4E98538A63031
         0E                             # unsigned(14)
         58 20                          # bytes(32)
            8CFE63E5E0BE75130C43039CF771200DB31D717F57834B59836F30B9F717604C
         13                             # unsigned(19)
         58 20                          # bytes(32)
            01318991E8782E32B513AADEB821ABF04F86D78F92C7EE1F3B8B74AF2F618008
         0A                             # unsigned(10)
         58 20                          # bytes(32)
            0EB07E37E35671D939EEC01583E7CADCA07E9F104B56F3FCEF71113EDCF29F02
         05                             # unsigned(5)
         58 20                          # bytes(32)
            9275CFF0E0C7895BCEA8F4D564A809ECB8F2172ACBDFD70618D2AAF3D7804925
      77                                # text(23)
         6F72672E69736F2E31383031332E352E312E61616D7661
      A6                                # map(6)
         0F                             # unsigned(15)
         58 20                          # bytes(32)
            1034DB3251BFE61F83D63A2AE173A49D90C18590A11C00F30D20B0172BB8402A
         09                             # unsigned(9)
         58 20                          # bytes(32)
            B803A515122AE93704A8DBF5925DEAF647922049D0B61309CD1E0542A4E45FBC
         14                             # unsigned(20)
         58 20                          # bytes(32)
            9F478AD625BE1D21E2D3765098DA13AB3DF82AA0B5B815D85A255418A6CF5EA2
         0C                             # unsigned(12)
         58 20                          # bytes(32)
            5D94ABC356D3EE59BB4C361D0299454B3143CC0D566C0D9CE39EEB74A3BF8BF9
         03                             # unsigned(3)
         58 20                          # bytes(32)
            14AEBF6225497589B495DB94EF25C1A439427F1E7000E622E2D8E31C25B7859F
         08                             # unsigned(8)
         58 20                          # bytes(32)
            7AC6CDCA8493DEE6A91AE97594B01A0670EE3F50AA16EEA6FB0EA04D9E8F8485
   6D                                   # text(13)
      6465766963654B6579496E666F        # "deviceKeyInfo"
   A1                                   # map(1)
      69                                # text(9)
         6465766963654B6579             # "deviceKey"
      A4                                # map(4)
         01                             # unsigned(1)
         02                             # unsigned(2)
         20                             # negative(0)
         01                             # unsigned(1)
         21                             # negative(1)
         58 20                          # bytes(32)
            7B8FB8726BEFFC40E76F00DCAFF8F479F0EBA054AF95A7CD3049C145FC66F321
         22                             # negative(2)
         58 20                          # bytes(32)
            859EEAE702FEB42E9403846788A0054259933B7BCCC9E7825831910B95A2772C
   6C                                   # text(12)
      76616C6964697479496E666F          # "validityInfo"
   A3                                   # map(3)
      66                                # text(6)
         7369676E6564                   # "signed"
      C0                                # tag(0)
         74                             # text(20)
            323032332D31302D31315431333A31383A31355A # "2023-10-11T13:18:15Z"
      69                                # text(9)
         76616C696446726F6D             # "validFrom"
      C0                                # tag(0)
         74                             # text(20)
            323032332D31302D31315431333A31383A31355A # "2023-10-11T13:18:15Z"
      6A                                # text(10)
         76616C6964556E74696C           # "validUntil"
      C0                                # tag(0)
         74                             # text(20)
            323032332D31312D31305431333A31383A31355A # "2023-11-10T13:18:15Z"

*/
static constexpr size_t mso_nbytes = 1068;
static const uint8_t mso_example[mso_nbytes] = {
    0xA6, 0x67, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6F, 0x6E, 0x63, 0x31, 0x2E,
    0x30, 0x6F, 0x64, 0x69, 0x67, 0x65, 0x73, 0x74, 0x41, 0x6C, 0x67, 0x6F,
    0x72, 0x69, 0x74, 0x68, 0x6D, 0x67, 0x53, 0x48, 0x41, 0x2D, 0x32, 0x35,
    0x36, 0x67, 0x64, 0x6F, 0x63, 0x54, 0x79, 0x70, 0x65, 0x75, 0x6F, 0x72,
    0x67, 0x2E, 0x69, 0x73, 0x6F, 0x2E, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2E,
    0x35, 0x2E, 0x31, 0x2E, 0x6D, 0x44, 0x4C, 0x6C, 0x76, 0x61, 0x6C, 0x75,
    0x65, 0x44, 0x69, 0x67, 0x65, 0x73, 0x74, 0x73, 0xA2, 0x71, 0x6F, 0x72,
    0x67, 0x2E, 0x69, 0x73, 0x6F, 0x2E, 0x31, 0x38, 0x30, 0x31, 0x33, 0x2E,
    0x35, 0x2E, 0x31, 0xAF, 0x0D, 0x58, 0x20, 0xB6, 0x28, 0x97, 0xFB, 0xDA,
    0x21, 0x39, 0x61, 0x40, 0x87, 0xA7, 0x3D, 0x0C, 0xE6, 0x3A, 0x16, 0xA0,
    0xBE, 0x43, 0x22, 0x5A, 0xC0, 0x5F, 0x6B, 0xE3, 0xDD, 0x77, 0x7F, 0xF5,
    0xD5, 0x69, 0xD2, 0x0B, 0x58, 0x20, 0x6F, 0x94, 0x84, 0xC8, 0x9B, 0x93,
    0x86, 0x44, 0xA4, 0x8E, 0x14, 0xA5, 0x79, 0x1F, 0x1C, 0x2A, 0x3B, 0x83,
    0xBA, 0x52, 0xBF, 0xB6, 0xCA, 0x0D, 0x9A, 0x3A, 0x8F, 0xD8, 0x44, 0xF3,
    0x5B, 0xD4, 0x04, 0x58, 0x20, 0x43, 0xCD, 0x17, 0x4E, 0x98, 0x85, 0xF2,
    0xF1, 0xF3, 0x2D, 0xF4, 0x74, 0x2F, 0x4F, 0x66, 0x2E, 0xB1, 0x8A, 0x9D,
    0xCB, 0x82, 0x62, 0x4B, 0x31, 0x65, 0x51, 0x2E, 0x1E, 0xA2, 0x41, 0xE1,
    0xAC, 0x07, 0x58, 0x20, 0x7E, 0xA1, 0x94, 0xA8, 0xB5, 0xC9, 0xCA, 0x0B,
    0xEC, 0x5C, 0x2E, 0x97, 0x9D, 0x9D, 0x8E, 0xFA, 0x2F, 0xE7, 0xC4, 0xCF,
    0xA8, 0x87, 0x13, 0xED, 0x50, 0xF9, 0x67, 0x91, 0x27, 0x24, 0xCB, 0x57,
    0x11, 0x58, 0x20, 0xBB, 0xCE, 0x5F, 0x31, 0x00, 0x89, 0xFE, 0xAD, 0xB8,
    0xB7, 0xA2, 0xC2, 0x39, 0xBC, 0x3E, 0x6F, 0xA9, 0x7E, 0xD1, 0x01, 0xC8,
    0x28, 0x7F, 0xF4, 0x8A, 0x4B, 0xDF, 0xF6, 0xCA, 0x37, 0xBE, 0xD2, 0x10,
    0x58, 0x20, 0xD2, 0xBD, 0xE3, 0x8E, 0x57, 0xAA, 0xB4, 0x8F, 0x34, 0x3C,
    0xF5, 0xDE, 0x25, 0x54, 0x0D, 0x9E, 0x23, 0x24, 0x36, 0x8C, 0x1D, 0x13,
    0x5A, 0x68, 0xFD, 0x0C, 0x0F, 0x78, 0x43, 0xCC, 0xB5, 0xDD, 0x01, 0x58,
    0x20, 0x73, 0x2C, 0xAA, 0x70, 0xD7, 0x49, 0x33, 0xD9, 0x08, 0x32, 0xC1,
    0x67, 0x9D, 0x00, 0x6C, 0x48, 0x07, 0x48, 0x62, 0x76, 0xAC, 0x9C, 0x86,
    0xB9, 0xC1, 0x83, 0x25, 0x7C, 0x7F, 0x1B, 0x23, 0xC5, 0x12, 0x58, 0x20,
    0x59, 0x3E, 0xBA, 0xA6, 0xA0, 0x7F, 0x27, 0x70, 0xB2, 0xD6, 0x03, 0x91,
    0x0F, 0x36, 0x77, 0xFF, 0x7B, 0x0A, 0xE9, 0xB6, 0xBE, 0x4A, 0x9D, 0xD8,
    0x60, 0x64, 0x49, 0x77, 0xD7, 0x26, 0xED, 0xA8, 0x06, 0x58, 0x20, 0x21,
    0xDC, 0x5A, 0xD5, 0xBA, 0x5B, 0x1A, 0x34, 0xC3, 0x38, 0xEC, 0x87, 0xFD,
    0xA6, 0x91, 0x0B, 0x59, 0xD4, 0x52, 0x76, 0x90, 0x6C, 0x80, 0x4D, 0xB1,
    0x39, 0x53, 0xAF, 0x0C, 0x75, 0xE5, 0xD1, 0x02, 0x58, 0x20, 0x2F, 0x44,
    0x53, 0x44, 0xE4, 0x86, 0x5E, 0x84, 0x7B, 0x39, 0xFC, 0x15, 0xB2, 0x85,
    0xA5, 0xEB, 0x40, 0xCC, 0x38, 0xB9, 0x9D, 0x6C, 0xD4, 0xB4, 0x61, 0x3E,
    0xC6, 0xA3, 0xE9, 0x33, 0x61, 0x48, 0x00, 0x58, 0x20, 0x34, 0x7B, 0xCC,
    0x0A, 0xB4, 0x88, 0xF3, 0x7F, 0x02, 0x0F, 0x66, 0x0D, 0xAC, 0x44, 0x71,
    0x23, 0x3A, 0x94, 0x45, 0xAA, 0xD9, 0x08, 0xBE, 0x3A, 0xDA, 0xC4, 0xE9,
    0x85, 0x38, 0xA6, 0x30, 0x31, 0x0E, 0x58, 0x20, 0x8C, 0xFE, 0x63, 0xE5,
    0xE0, 0xBE, 0x75, 0x13, 0x0C, 0x43, 0x03, 0x9C, 0xF7, 0x71, 0x20, 0x0D,
    0xB3, 0x1D, 0x71, 0x7F, 0x57, 0x83, 0x4B, 0x59, 0x83, 0x6F, 0x30, 0xB9,
    0xF7, 0x17, 0x60, 0x4C, 0x13, 0x58, 0x20, 0x01, 0x31, 0x89, 0x91, 0xE8,
    0x78, 0x2E, 0x32, 0xB5, 0x13, 0xAA, 0xDE, 0xB8, 0x21, 0xAB, 0xF0, 0x4F,
    0x86, 0xD7, 0x8F, 0x92, 0xC7, 0xEE, 0x1F, 0x3B, 0x8B, 0x74, 0xAF, 0x2F,
    0x61, 0x80, 0x08, 0x0A, 0x58, 0x20, 0x0E, 0xB0, 0x7E, 0x37, 0xE3, 0x56,
    0x71, 0xD9, 0x39, 0xEE, 0xC0, 0x15, 0x83, 0xE7, 0xCA, 0xDC, 0xA0, 0x7E,
    0x9F, 0x10, 0x4B, 0x56, 0xF3, 0xFC, 0xEF, 0x71, 0x11, 0x3E, 0xDC, 0xF2,
    0x9F, 0x02, 0x05, 0x58, 0x20, 0x92, 0x75, 0xCF, 0xF0, 0xE0, 0xC7, 0x89,
    0x5B, 0xCE, 0xA8, 0xF4, 0xD5, 0x64, 0xA8, 0x09, 0xEC, 0xB8, 0xF2, 0x17,
    0x2A, 0xCB, 0xDF, 0xD7, 0x06, 0x18, 0xD2, 0xAA, 0xF3, 0xD7, 0x80, 0x49,
    0x25, 0x77, 0x6F, 0x72, 0x67, 0x2E, 0x69, 0x73, 0x6F, 0x2E, 0x31, 0x38,
    0x30, 0x31, 0x33, 0x2E, 0x35, 0x2E, 0x31, 0x2E, 0x61, 0x61, 0x6D, 0x76,
    0x61, 0xA6, 0x0F, 0x58, 0x20, 0x10, 0x34, 0xDB, 0x32, 0x51, 0xBF, 0xE6,
    0x1F, 0x83, 0xD6, 0x3A, 0x2A, 0xE1, 0x73, 0xA4, 0x9D, 0x90, 0xC1, 0x85,
    0x90, 0xA1, 0x1C, 0x00, 0xF3, 0x0D, 0x20, 0xB0, 0x17, 0x2B, 0xB8, 0x40,
    0x2A, 0x09, 0x58, 0x20, 0xB8, 0x03, 0xA5, 0x15, 0x12, 0x2A, 0xE9, 0x37,
    0x04, 0xA8, 0xDB, 0xF5, 0x92, 0x5D, 0xEA, 0xF6, 0x47, 0x92, 0x20, 0x49,
    0xD0, 0xB6, 0x13, 0x09, 0xCD, 0x1E, 0x05, 0x42, 0xA4, 0xE4, 0x5F, 0xBC,
    0x14, 0x58, 0x20, 0x9F, 0x47, 0x8A, 0xD6, 0x25, 0xBE, 0x1D, 0x21, 0xE2,
    0xD3, 0x76, 0x50, 0x98, 0xDA, 0x13, 0xAB, 0x3D, 0xF8, 0x2A, 0xA0, 0xB5,
    0xB8, 0x15, 0xD8, 0x5A, 0x25, 0x54, 0x18, 0xA6, 0xCF, 0x5E, 0xA2, 0x0C,
    0x58, 0x20, 0x5D, 0x94, 0xAB, 0xC3, 0x56, 0xD3, 0xEE, 0x59, 0xBB, 0x4C,
    0x36, 0x1D, 0x02, 0x99, 0x45, 0x4B, 0x31, 0x43, 0xCC, 0x0D, 0x56, 0x6C,
    0x0D, 0x9C, 0xE3, 0x9E, 0xEB, 0x74, 0xA3, 0xBF, 0x8B, 0xF9, 0x03, 0x58,
    0x20, 0x14, 0xAE, 0xBF, 0x62, 0x25, 0x49, 0x75, 0x89, 0xB4, 0x95, 0xDB,
    0x94, 0xEF, 0x25, 0xC1, 0xA4, 0x39, 0x42, 0x7F, 0x1E, 0x70, 0x00, 0xE6,
    0x22, 0xE2, 0xD8, 0xE3, 0x1C, 0x25, 0xB7, 0x85, 0x9F, 0x08, 0x58, 0x20,
    0x7A, 0xC6, 0xCD, 0xCA, 0x84, 0x93, 0xDE, 0xE6, 0xA9, 0x1A, 0xE9, 0x75,
    0x94, 0xB0, 0x1A, 0x06, 0x70, 0xEE, 0x3F, 0x50, 0xAA, 0x16, 0xEE, 0xA6,
    0xFB, 0x0E, 0xA0, 0x4D, 0x9E, 0x8F, 0x84, 0x85, 0x6D, 0x64, 0x65, 0x76,
    0x69, 0x63, 0x65, 0x4B, 0x65, 0x79, 0x49, 0x6E, 0x66, 0x6F, 0xA1, 0x69,
    0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x4B, 0x65, 0x79, 0xA4, 0x01, 0x02,
    0x20, 0x01, 0x21, 0x58, 0x20, 0x7B, 0x8F, 0xB8, 0x72, 0x6B, 0xEF, 0xFC,
    0x40, 0xE7, 0x6F, 0x00, 0xDC, 0xAF, 0xF8, 0xF4, 0x79, 0xF0, 0xEB, 0xA0,
    0x54, 0xAF, 0x95, 0xA7, 0xCD, 0x30, 0x49, 0xC1, 0x45, 0xFC, 0x66, 0xF3,
    0x21, 0x22, 0x58, 0x20, 0x85, 0x9E, 0xEA, 0xE7, 0x02, 0xFE, 0xB4, 0x2E,
    0x94, 0x03, 0x84, 0x67, 0x88, 0xA0, 0x05, 0x42, 0x59, 0x93, 0x3B, 0x7B,
    0xCC, 0xC9, 0xE7, 0x82, 0x58, 0x31, 0x91, 0x0B, 0x95, 0xA2, 0x77, 0x2C,
    0x6C, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x69, 0x74, 0x79, 0x49, 0x6E, 0x66,
    0x6F, 0xA3, 0x66, 0x73, 0x69, 0x67, 0x6E, 0x65, 0x64, 0xC0, 0x74, 0x32,
    0x30, 0x32, 0x33, 0x2D, 0x31, 0x30, 0x2D, 0x31, 0x31, 0x54, 0x31, 0x33,
    0x3A, 0x31, 0x38, 0x3A, 0x31, 0x35, 0x5A, 0x69, 0x76, 0x61, 0x6C, 0x69,
    0x64, 0x46, 0x72, 0x6F, 0x6D, 0xC0, 0x74, 0x32, 0x30, 0x32, 0x33, 0x2D,
    0x31, 0x30, 0x2D, 0x31, 0x31, 0x54, 0x31, 0x33, 0x3A, 0x31, 0x38, 0x3A,
    0x31, 0x35, 0x5A, 0x6A, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x55, 0x6E, 0x74,
    0x69, 0x6C, 0xC0, 0x74, 0x32, 0x30, 0x32, 0x33, 0x2D, 0x31, 0x31, 0x2D,
    0x31, 0x30, 0x54, 0x31, 0x33, 0x3A, 0x31, 0x38, 0x3A, 0x31, 0x35, 0x5A,
};

TEST(MSO, Example2) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  using Cbor = Cbor<Logic>;
  const Cbor CBOR(L);
  const CborTesting CT(F);
  const CborWitness CW(F);

  constexpr size_t n = 2000;
  size_t input_len = mso_nbytes;
  EXPECT_LE(input_len, n);

  std::vector<uint8_t> bytes(n);
  // pad with zeroes
  for (size_t i = 0; i + input_len < n; ++i) {
    bytes[i] = 0;
  }
  for (size_t i = 0; i < input_len; ++i) {
    bytes[i + n - input_len] = mso_example[i];
  }

  std::vector<CborWitness::v8> inS(n);
  std::vector<CborWitness::position_witness> pwS(n);
  CborWitness::global_witness gwS;
  CW.fill_witnesses(n, input_len, bytes.data(), inS.data(), pwS.data(), gwS);

  std::vector<Cbor::v8> in(n);
  std::vector<Cbor::position_witness> pw(n);
  Cbor::global_witness gw;
  CT.convert_witnesses(n, in.data(), pw.data(), gw, inS.data(), pwS.data(),
                       gwS);

  std::vector<Cbor::decode> ds(n);
  std::vector<Cbor::parse_output> ps(n);
  CBOR.decode_and_assert_decode_and_parse(n, ds.data(), ps.data(), in.data(),
                                          pw.data(), gw);
}

TEST(MSO, Various) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  using Cbor = Cbor<Logic>;
  const Cbor CBOR(L);
  const CborTesting CT(F);
  const CborWitness CW(F);

  constexpr size_t n = mso_nbytes;

  // compile-time
  size_t input_len = n;
  std::vector<CborWitness::v8> inS(n);
  std::vector<CborWitness::position_witness> pwS(n);
  CborWitness::global_witness gwS;
  CW.fill_witnesses(n, input_len, mso_example, inS.data(), pwS.data(), gwS);

  std::vector<Cbor::v8> in(n);
  std::vector<Cbor::position_witness> pw(n);
  Cbor::global_witness gw;
  CT.convert_witnesses(n, in.data(), pw.data(), gw, inS.data(), pwS.data(),
                       gwS);

  // circuit-time
  std::vector<Cbor::decode> ds(n);
  std::vector<Cbor::parse_output> ps(n);
  CBOR.decode_and_assert_decode_and_parse(n, ds.data(), ps.data(), in.data(),
                                          pw.data(), gw);

  // sanity check on the output
  for (size_t i = 0; i < n; ++i) {
    for (size_t l = 0; l < CborConstants::kNCounters; ++l) {
      EXPECT_EQ(F.as_counter(pwS[i].cc_debug[l]).e, ps[i].c[l].e.elt());
    }
  }

  static const uint8_t bytes[15] = {
      'd', 'i', 'g', 'e', 's', 't', 'A', 'l', 'g', 'o', 'r', 'i', 't', 'h', 'm',
  };

  CBOR.assert_header(n, CT.index(13), ds.data());
  CBOR.assert_text_at(n, CT.index(13), 15, bytes, ds.data());
  CBOR.assert_map_header(n, CT.index(80), ds.data());
}

static const uint8_t svalueDigests[12] = {
    'v', 'a', 'l', 'u', 'e', 'D', 'i', 'g', 'e', 's', 't', 's',
};

static const uint8_t sorgBlahBlahBlah[17] = {
    'o', 'r', 'g', '.', 'i', 's', 'o', '.', '1',
    '8', '0', '1', '3', '.', '5', '.', '1',
};

TEST(MSO, MapLookup) {
  const EvalBackend ebk(F);
  const Logic L(&ebk, F);
  using Cbor = Cbor<Logic>;
  const Cbor CBOR(L);
  const CborTesting CT(F);
  const CborWitness CW(F);

  constexpr size_t n = 2000;
  constexpr size_t input_len = mso_nbytes;
  EXPECT_LE(input_len, n);

  std::vector<uint8_t> bytes(n);
  // pad with zeroes
  for (size_t i = 0; i < n - input_len; ++i) {
    bytes[i] = 0;
  }
  for (size_t i = 0; i < input_len; ++i) {
    bytes[i + n - input_len] = mso_example[i];
  }

  // compile-time
  std::vector<CborWitness::v8> inS(n);
  std::vector<CborWitness::position_witness> pwS(n);
  CborWitness::global_witness gwS;
  CW.fill_witnesses(n, input_len, bytes.data(), inS.data(), pwS.data(), gwS);

  std::vector<Cbor::v8> in(n);
  std::vector<Cbor::position_witness> pw(n);
  Cbor::global_witness gw;
  CT.convert_witnesses(n, in.data(), pw.data(), gw, inS.data(), pwS.data(),
                       gwS);

  size_t pos = 0;
  size_t offset = n - input_len;
  CborDoc croot;
  bool ret = croot.decode(mso_example, mso_nbytes, pos, offset);
  EXPECT_TRUE(ret);
  EXPECT_EQ(pos, mso_nbytes);
  EXPECT_EQ(croot.header_pos_, offset);

  size_t vdndx;
  const CborDoc* vd =
      croot.lookup(mso_example, sizeof(svalueDigests), svalueDigests, vdndx);
  EXPECT_NE(vd, nullptr);
  size_t orgndx;
  const CborDoc* org = vd[1].lookup(mso_example, sizeof(sorgBlahBlahBlah),
                                    sorgBlahBlahBlah, orgndx);
  EXPECT_NE(org, nullptr);

  size_t org_lookup_tag = 4;
  size_t hashndx;
  const CborDoc* hash = org[1].lookup_unsigned(org_lookup_tag, hashndx);
  EXPECT_NE(hash, nullptr);

  // circuit-time
  std::vector<Cbor::decode> ds(n);
  std::vector<Cbor::parse_output> ps(n);
  auto input_lenW = CT.index(input_len);
  CBOR.decode_and_assert_decode_and_parse(n, ds.data(), ps.data(), in.data(),
                                          pw.data(), gw);

  // sanity check on the output
  for (size_t i = 0; i < n; ++i) {
    for (size_t l = 0; l < CborConstants::kNCounters; ++l) {
      EXPECT_EQ(F.as_counter(pwS[i].cc_debug[l]).e, ps[i].c[l].e.elt());
    }
  }

  // the top-level map axiomatically starts at position OFFSET
  auto jroot = CT.index(offset);
  CBOR.assert_input_starts_at(n, jroot, input_lenW, ds.data());

  // "Position JROOT starts a map of level 0.  (JVDK, JVDV) are headers
  // representing the VDNDX-th pair in that map.  The key at JVDK is
  // correct."
  auto jvdk = CT.index(vd[0].header_pos_);
  auto jvdv = CT.index(vd[1].header_pos_);
  CBOR.assert_map_entry(n, jroot, 0, jvdk, jvdv, CT.index(vdndx), ds.data(),
                        ps.data());
  CBOR.assert_text_at(n, jvdk, sizeof(svalueDigests), svalueDigests, ds.data());

  // "Position JVDV starts a map of level 1.
  // (JORGK, JORGV) are headers representing the ORGNDX-th pair in
  // that map. The key at JORGK is correct."
  auto jorgk = CT.index(org[0].header_pos_);
  auto jorgv = CT.index(org[1].header_pos_);
  CBOR.assert_map_entry(n, jvdv, 1, jorgk, jorgv, CT.index(orgndx), ds.data(),
                        ps.data());
  CBOR.assert_text_at(n, jorgk, sizeof(sorgBlahBlahBlah), sorgBlahBlahBlah,
                      ds.data());

  // Position JORGV starts a map of level 2.
  // (JHASHK, JHASHV) are headers representing the HASHNDX-th pair in
  // that map. The key at JHASHK is correct."
  auto jhashk = CT.index(hash[0].header_pos_);
  auto jhashv = CT.index(hash[1].header_pos_);
  CBOR.assert_map_entry(n, jorgv, 2, jhashk, jhashv, CT.index(hashndx),
                        ds.data(), ps.data());
  CBOR.assert_unsigned_at(n, jhashk, org_lookup_tag, ds.data());

  // Old assertion that does not work in binary fields.
  // The old assert_elt_as_be_bytes_at() has been removed
  // and there is no point in replacing it with some other
  // code that is not used except in tests.
  //
  // However, we leave this comment around because anybody
  // who wants to use this test as a starting point will
  // need to remember to compare the actual contents at jhashv
  // against something.

  // JHASHV is a 32-byte string
  //
  // auto a4 = L.konst(L.elt(
  // "0x43CD174E9885F2F1F32DF4742F4F662EB18A9DCB82624B3165512E1EA241E1AC"));
  // CBOR.assert_elt_as_be_bytes_at(n, jhashv, 32, a4, ds.data());
}

// test for real, prover and verifier
TEST(MSO, Example2Real) {
  set_log_level(INFO);

  constexpr size_t nc = 1;
  constexpr size_t n = 2000;
  constexpr size_t input_len = mso_nbytes;
  EXPECT_LE(input_len, n);

  size_t org_lookup_tag = 4;

  // COMPILE TIME.
  size_t ninput;
  std::unique_ptr<Circuit<Field>> CIRCUIT;
  size_t offset = n - input_len;

  log(INFO, "MSO End to End Start");

  /*scope to delimit compile-time*/ {
    QuadCircuit<Field> Q(F);
    const CompilerBackend cbk(&Q);
    const LogicCircuit LC(&cbk, F);
    const Counter<LogicCircuit> CTRC(LC);
    using CborC = Cbor<LogicCircuit>;
    const CborC CBORC(LC);
    std::vector<CborC::v8> inC(n);
    std::vector<CborC::position_witness> pwC(n);
    CborC::global_witness gwC;

    auto input_lenC = LC.vinput<CborC::kIndexBits>();
    for (size_t i = 0; i < n; ++i) {
      inC[i] = LC.vinput<8>();
      pwC[i].encoded_sel_header = LC.eltw_input();
    }
    gwC.invprod_decode = LC.eltw_input();
    gwC.cc0_counter = CTRC.input();
    gwC.invprod_parse = LC.eltw_input();

    std::vector<CborC::decode> dsC(n);
    std::vector<CborC::parse_output> psC(n);
    CBORC.decode_and_assert_decode_and_parse(n, dsC.data(), psC.data(),
                                             inC.data(), pwC.data(), gwC);

    // the top-level map axiomatically starts at position jroot
    // such that jroot + input_len == n
    auto jrootC = LC.vinput<CborC::kIndexBits>();
    CBORC.assert_input_starts_at(n, jrootC, input_lenC, dsC.data());

    // "Position JROOT starts a map of level 0.  (JVDK, JVDV) are headers
    // representing the VDNDX-th pair in that map.  The key at JVDK is
    // correct."
    auto jvdkC = LC.vinput<CborC::kIndexBits>();
    auto jvdvC = LC.vinput<CborC::kIndexBits>();
    auto vdndxC = LC.vinput<CborC::kIndexBits>();

    CBORC.assert_map_entry(n, jrootC, 0, jvdkC, jvdvC, vdndxC, dsC.data(),
                           psC.data());

    CBORC.assert_text_at(n, jvdkC, sizeof(svalueDigests), svalueDigests,
                         dsC.data());

    // "Position JVDV starts a map of level 1.
    // (JORGK, JORGV) are headers representing the ORGNDX-th pair in
    // that map. The key at JORGK is correct."
    auto jorgkC = LC.vinput<CborC::kIndexBits>();
    auto jorgvC = LC.vinput<CborC::kIndexBits>();
    auto orgndxC = LC.vinput<CborC::kIndexBits>();

    CBORC.assert_map_entry(n, jvdvC, 1, jorgkC, jorgvC, orgndxC, dsC.data(),
                           psC.data());

    CBORC.assert_text_at(n, jorgkC, sizeof(sorgBlahBlahBlah), sorgBlahBlahBlah,
                         dsC.data());

    // Position JORGV starts a map of level 2.
    // (JHASHK, JHASHV) are headers representing the HASHNDX-th pair in
    // that map. The key at JHASHK is correct."
    auto jhashkC = LC.vinput<CborC::kIndexBits>();
    auto jhashvC = LC.vinput<CborC::kIndexBits>();
    auto hashndxC = LC.vinput<CborC::kIndexBits>();

    CBORC.assert_map_entry(n, jorgvC, 2, jhashkC, jhashvC, hashndxC, dsC.data(),
                           psC.data());
    CBORC.assert_unsigned_at(n, jhashkC, org_lookup_tag, dsC.data());

    CIRCUIT = Q.mkcircuit(/*nc=*/1);
    dump_info<Field>("mso2 decode_and_assert_decode_and_parse", Q);
    ninput = Q.ninput();
  }
  log(INFO, "Compile done");

  /*------------------------------------------------------------*/
  // Witness-creation time

  // copy the real input into BYTES
  std::vector<uint8_t> bytes(n);
  // pad with zeroes
  for (size_t i = 0; i + input_len < n; ++i) {
    bytes[i] = 0;
  }
  for (size_t i = 0; i < input_len; ++i) {
    bytes[i + n - input_len] = mso_example[i];
  }

  // parsing witnesses
  std::vector<CborWitness::v8> inS(n);
  std::vector<CborWitness::position_witness> pwS(n);
  CborWitness::global_witness gwS;
  const CborWitness CW(F);
  CW.fill_witnesses(n, input_len, bytes.data(), inS.data(), pwS.data(), gwS);

  // path witnesses
  size_t pos = 0;
  CborDoc croot;
  bool ret = croot.decode(mso_example, mso_nbytes, pos, offset);
  EXPECT_TRUE(ret);
  EXPECT_EQ(pos, mso_nbytes);
  EXPECT_EQ(croot.header_pos_, offset);

  size_t vdndx;
  const CborDoc* vd =
      croot.lookup(mso_example, sizeof(svalueDigests), svalueDigests, vdndx);
  EXPECT_NE(vd, nullptr);

  size_t orgndx;
  const CborDoc* org = vd[1].lookup(mso_example, sizeof(sorgBlahBlahBlah),
                                    sorgBlahBlahBlah, orgndx);
  EXPECT_NE(org, nullptr);

  size_t hashndx;
  const CborDoc* hash = org[1].lookup_unsigned(org_lookup_tag, hashndx);
  EXPECT_NE(hash, nullptr);

  /*------------------------------------------------------------*/
  // Fill inputs
  auto W = std::make_unique<Dense<Field>>(nc, ninput);
  DenseFiller<Field> filler(*W);

  filler.push_back(F.one());
  filler.push_back(CW.index(input_len));

  for (size_t i = 0; i < n; ++i) {
    filler.push_back(inS[i]);
    filler.push_back(pwS[i].encoded_sel_header);
  }
  filler.push_back(gwS.invprod_decode);
  filler.push_back(gwS.cc0_counter.e);
  filler.push_back(gwS.invprod_parse);

  // jroot
  filler.push_back(CW.index(offset));

  // jvdk, jvdv, vdndx
  filler.push_back(CW.index(vd[0].header_pos_));
  filler.push_back(CW.index(vd[1].header_pos_));
  filler.push_back(CW.index(vdndx));

  // jorgk, jorgv, orgndx
  filler.push_back(CW.index(org[0].header_pos_));
  filler.push_back(CW.index(org[1].header_pos_));
  filler.push_back(CW.index(orgndx));

  // jhashk, jhashv, hashndx
  filler.push_back(CW.index(hash[0].header_pos_));
  filler.push_back(CW.index(hash[1].header_pos_));
  filler.push_back(CW.index(hashndx));

  log(INFO, "Witness filled");

  /*------------------------------------------------------------*/
  // Prove
  Proof<Field> proof(CIRCUIT->nl);
  run_prover<Field>(CIRCUIT.get(), W->clone(), &proof, F);
  log(INFO, "Prove done");

  /*------------------------------------------------------------*/
  // Verify
  run_verifier<Field>(CIRCUIT.get(), W->clone(), proof, F);
  log(INFO, "Verifier done");
}

}  // namespace
}  // namespace proofs
