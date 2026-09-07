// Copyright 2026 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef PRIVACY_PROOFS_ZK_LIB_UTIL_SECURE_WIPE_H_
#define PRIVACY_PROOFS_ZK_LIB_UTIL_SECURE_WIPE_H_

#include <cstddef>
#include <type_traits>
#include <vector>

namespace proofs {

// Volatile byte stores prevent the compiler from removing this wipe as a
// dead write when the containing object is about to be destroyed.
inline void secure_wipe_bytes(void* data, size_t size) noexcept {
  auto* out = static_cast<volatile unsigned char*>(data);
  while (size-- != 0) {
    *out++ = 0;
  }
}

template <typename T>
inline void secure_wipe_object(T& value) noexcept {
  static_assert(std::is_trivially_copyable_v<T>,
                "secure_wipe_object requires trivially copyable storage");
  secure_wipe_bytes(&value, sizeof(value));
}

template <typename T, typename Allocator>
inline void secure_wipe_vector(std::vector<T, Allocator>& values) noexcept {
  static_assert(std::is_trivially_copyable_v<T>,
                "secure_wipe_vector requires trivially copyable elements");
  if (!values.empty()) {
    secure_wipe_bytes(values.data(), values.size() * sizeof(T));
  }
}

template <typename T>
class SecureWipeGuard {
 public:
  explicit SecureWipeGuard(std::vector<T>& values) noexcept : values_(&values) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "SecureWipeGuard requires trivially copyable elements");
  }
  SecureWipeGuard(const SecureWipeGuard&) = delete;
  SecureWipeGuard& operator=(const SecureWipeGuard&) = delete;
  ~SecureWipeGuard() { secure_wipe_vector(*values_); }

 private:
  std::vector<T>* values_;
};

template <typename T>
class SecureObjectWipeGuard {
 public:
  explicit SecureObjectWipeGuard(T& value) noexcept : value_(&value) {
    static_assert(std::is_trivially_copyable_v<T>,
                  "SecureObjectWipeGuard requires trivially copyable storage");
  }
  SecureObjectWipeGuard(const SecureObjectWipeGuard&) = delete;
  SecureObjectWipeGuard& operator=(const SecureObjectWipeGuard&) = delete;
  ~SecureObjectWipeGuard() { secure_wipe_object(*value_); }

 private:
  T* value_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_SECURE_WIPE_H_
