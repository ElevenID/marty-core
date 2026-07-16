// Copyright 2025 Google LLC.
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

// This program generates a circuit for mdoc_zk, computes its ID, and writes
// the circuit to a file named after the circuit ID in a specified output
// directory.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <absl/cleanup/cleanup.h>
#include <absl/flags/flag.h>
#include <absl/flags/parse.h>

#include "circuits/mdoc/mdoc_zk.h"
#include "util/log.h"
#include "util/panic.h"
#include "util/readbuffer.h"
#include "zk/zk_common.h"
#include "circuits/mdoc/mdoc_decompress.h"
#include "ec/p256.h"
#include "gf2k/gf2_128.h"
#include "ligero/ligero_param.h"
#include "proto/circuit.h"


ABSL_FLAG(std::string, output_dir, "circuits",
          "Output directory for the circuit file");
ABSL_FLAG(int, num_attributes, 1,
          "Number of attributes for the circuit (selects ZkSpec)");

std::string BytesToHexString(const uint8_t* bytes, size_t len) {
  std::stringstream ss;
  ss << std::hex << std::setfill('0');
  for (size_t i = 0; i < len; ++i) {
    ss << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return ss.str();
}

// Recompute the parameters to find the optimal fine grained block_enc.
template <class LigeroParam>
size_t optimize(LigeroParam &lp) {
  size_t min_proof_size = lp.layout(lp.block_enc);
  size_t best_block_enc = lp.block_enc;
  for (size_t e = 100; e <= (1 << 17); e++) {
    size_t proof_size = lp.layout(e);
    if (proof_size < min_proof_size) {
      min_proof_size = proof_size;
      best_block_enc = e;
    }
  }
  return best_block_enc;
}

// Decompress and parse the circuit bytes, optimize the Ligero
// commitment parameters and print a ZkSpecStruct entry.
void optimize_params(const uint8_t* circuit_bytes, size_t circuit_len,
                     const std::string& circuit_id_hex,
                     const ZkSpecStruct* zk_spec) {
  using f_128 = proofs::GF2_128<>;
  // Parse circuits.
  const f_128 Fs;

  size_t len = 1 << 27;
  std::vector<uint8_t> bytes(len);
  size_t full_size = proofs::decompress(bytes, circuit_bytes, circuit_len);

  // Ensure that the circuit was decompressed correctly.
  proofs::check(full_size > 0, "Circuit decompression failed");
  proofs::ReadBuffer rb_circuit(bytes.data(), full_size);

  proofs::CircuitRep<proofs::Fp256Base> cr_s(proofs::p256_base,
                                             proofs::P256_ID);
  auto c_sig = cr_s.from_bytes(rb_circuit, false);
  proofs::check(c_sig != nullptr, "Signature circuit could not be parsed");

  proofs::CircuitRep<f_128> cr_h(Fs, proofs::GF2_128_ID);
  auto c_hash = cr_h.from_bytes(rb_circuit, false);
  proofs::check(c_hash != nullptr, "Hash circuit could not be parsed");

  proofs::LigeroParam<f_128> hp(
      (c_hash->ninputs - c_hash->npub_in) +
          proofs::ZkCommon<f_128>::pad_size(*c_hash),
      c_hash->nl, kLigeroRate, kLigeroNreq);

  size_t min_proof_size = hp.layout(hp.block_enc);
  std::cout << "  hash legacy parameters: be:" << hp.block_enc
            << " sz:" << min_proof_size << " r:" << hp.r << " w:" << hp.w
            << " b:" << hp.block << " nr:" << hp.nrow << " nq:" << hp.nqtriples
            << std::endl;
  size_t best_block_enc = optimize(hp);
  min_proof_size = hp.layout(best_block_enc);
  std::cout << "  hash   best parameters: be:" << best_block_enc
            << " sz:" << min_proof_size << std::endl;

  proofs::LigeroParam<proofs::Fp256Base> sp(
      (c_sig->ninputs - c_sig->npub_in) +
          proofs::ZkCommon<proofs::Fp256Base>::pad_size(*c_sig),
      c_sig->nl, kLigeroRate, kLigeroNreq);

  min_proof_size = sp.layout(sp.block_enc);

  std::cout << "   sig legacy parameters: be:" << sp.block_enc
            << " sz:" << min_proof_size << " r:" << sp.r << " w:" << sp.w
            << " b:" << sp.block << " nr:" << sp.nrow << " nq:" << sp.nqtriples
            << std::endl;

  size_t sig_best_block_enc = optimize(sp);
  min_proof_size = sp.layout(sig_best_block_enc);

  std::cout << "   sig   best parameters: be:" << sig_best_block_enc
            << " sz:" << min_proof_size << std::endl;

  std::cout << "{\"" << zk_spec->system << "\", \"" << circuit_id_hex << "\", "
            << zk_spec->num_attributes << ", " << zk_spec->version << ", "
            << best_block_enc << ", " << sig_best_block_enc << "},"
            << std::endl;
}

// Helper to find a ZkSpecStruct matching the desired number of attributes.
// If no exact match, returns nullptr. In a real scenario, you might pick the
// latest or closest one, or error out.
const ZkSpecStruct* FindZkSpecByNumAttributes(int n_attrs) {
  for (size_t i = 0; i < kNumZkSpecs; ++i) {
    if (static_cast<int>(kZkSpecs[i].num_attributes) == n_attrs) {
      return &kZkSpecs[i];
    }
  }
  return nullptr;  // Or handle as an error, or pick a default.
}

int main(int argc, char* argv[]) {
  absl::ParseCommandLine(argc, argv);
  proofs::set_log_level(proofs::ERROR);

  std::string output_dir_path = absl::GetFlag(FLAGS_output_dir);
  int n_attributes_requested = absl::GetFlag(FLAGS_num_attributes);
  std::cout << "Output directory: " << output_dir_path << std::endl;
  std::cout << "Requested number of attributes: " << n_attributes_requested
            << std::endl;

  // Find a ZkSpecStruct based on the number of attributes requested
  const ZkSpecStruct* selected_zk_spec =
      FindZkSpecByNumAttributes(n_attributes_requested);
  if (selected_zk_spec == nullptr) {
    std::cerr << "Error: No ZkSpec available in kZkSpecs array." << std::endl;
    return 1;
  }

  std::cout << "Using ZkSpec: " << selected_zk_spec->system
            << ", version: " << selected_zk_spec->version
            << ", attributes: " << selected_zk_spec->num_attributes
            << std::endl;

  std::ifstream dir(output_dir_path, std::ios::binary);
  if (!dir.is_open()) {
    std::cerr << "Error: Could not open dir  " << output_dir_path << std::endl;
    return 1;
  }
  dir.close();

  uint8_t* circuit_bytes = nullptr;
  size_t circuit_len = 0;
  // Use absl mechanism to ensure that the memory is freed.
  absl::Cleanup free_circuit_bytes = [&circuit_bytes] {
    if (circuit_bytes) {
      free(circuit_bytes);  // mdoc_zk.h uses C-style allocation
    }
  };

  std::cout << "Generating circuit..." << std::endl;
  CircuitGenerationErrorCode circuit_gen_status =
      generate_circuit(selected_zk_spec, &circuit_bytes, &circuit_len);
  if (circuit_gen_status != CIRCUIT_GENERATION_SUCCESS) {
    std::cerr << "Error generating circuit. Code: " << circuit_gen_status
              << std::endl;
    return 1;
  }
  if (circuit_bytes == nullptr || circuit_len == 0) {
    std::cerr << "Error: generate_circuit succeeded but output is empty."
              << std::endl;
    return 1;
  }
  std::cout << "Circuit generated successfully. Size: " << circuit_len
            << " bytes." << std::endl;

  // Compute circuit ID.
  constexpr size_t kSHA256DigestSize = 32;
  uint8_t c_id[kSHA256DigestSize];
  std::cout << "Computing circuit ID." << std::endl;
  if (!circuit_id(c_id, circuit_bytes, circuit_len, selected_zk_spec)) {
    std::cerr << "Error computing circuit ID." << std::endl;
    return 1;
  }
  std::string circuit_id_hex = BytesToHexString(c_id, kSHA256DigestSize);
  std::cout << "Circuit ID (hex): " << circuit_id_hex << std::endl;

  // Write circuit bytes to file.
  namespace fs = std::filesystem;
  std::string output_file_path = (fs::path(output_dir_path) / fs::path(circuit_id_hex)).string();
  std::cout << "Writing circuit to: " << output_file_path << std::endl;
  std::ofstream out_file(output_file_path, std::ios::binary | std::ios::trunc);
  if (!out_file.is_open()) {
    std::cerr << "Error: Could not open file for writing: " << output_file_path
              << std::endl;
    return 1;
  }
  out_file.write(reinterpret_cast<const char*>(circuit_bytes), circuit_len);
  if (!out_file) {  // Check for write errors
    std::cerr << "Error writing circuit to file: " << output_file_path
              << std::endl;
    out_file.close();
    return 1;
  }
  out_file.close();
  std::cout << "Circuit successfully written to " << output_file_path
            << std::endl;

  // Search for optimal Ligero parameters.
  std::cout << "Optimizing Ligero parameters..." << std::endl;
  optimize_params(circuit_bytes, circuit_len, circuit_id_hex, selected_zk_spec);
  return 0;
}
