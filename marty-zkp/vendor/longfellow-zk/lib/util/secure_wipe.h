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
#include <cstdlib>
#include <type_traits>
#include <utility>
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

// Wipe a sensitive vector and restore its original logical length on every
// exit path. The retained length must not exceed the vector's size while the
// guard is alive.
template <typename T>
class SecureVectorResetGuard {
 public:
  SecureVectorResetGuard(std::vector<T>& values, size_t retained_size) noexcept
      : values_(&values), retained_size_(retained_size) {
    static_assert(std::is_trivially_copyable_v<T>);
    if (retained_size_ > values_->size()) {
      std::abort();
    }
  }
  SecureVectorResetGuard(const SecureVectorResetGuard&) = delete;
  SecureVectorResetGuard& operator=(const SecureVectorResetGuard&) = delete;
  ~SecureVectorResetGuard() {
    secure_wipe_vector(*values_);
    if (retained_size_ > values_->size()) {
      std::abort();
    }
    values_->resize(retained_size_);
  }

 private:
  std::vector<T>* values_;
  size_t retained_size_;
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

template <typename T, typename Operation>
void with_secure_scratch(T& scratch, Operation&& operation) {
  SecureObjectWipeGuard<T> wipe(scratch);
  std::forward<Operation>(operation)(scratch);
}

// Use after reserving the complete sensitive payload. All mutation of the
// guarded vector must go through this guard so capacity is checked before a
// mutation can free an earlier secret allocation.
template <typename T>
class FixedCapacitySecureWipeGuard {
 public:
  explicit FixedCapacitySecureWipeGuard(std::vector<T>& values) noexcept
      : values_(&values), data_(values.data()), capacity_(values.capacity()) {
    static_assert(std::is_trivially_copyable_v<T>);
  }
  FixedCapacitySecureWipeGuard(const FixedCapacitySecureWipeGuard&) = delete;
  FixedCapacitySecureWipeGuard& operator=(
      const FixedCapacitySecureWipeGuard&) = delete;

  bool can_append(size_t count) const noexcept {
    return values_->data() == data_ && values_->capacity() == capacity_ &&
           values_->size() <= capacity_ && count <= capacity_ - values_->size();
  }

  void push_back(const T& value) {
    require_remaining(1);
    values_->push_back(value);
  }

  template <typename U>
  void append(const U* values, size_t count) {
    require_remaining(count);
    for (size_t i = 0; i < count; ++i) {
      values_->push_back(static_cast<T>(values[i]));
    }
  }

  ~FixedCapacitySecureWipeGuard() {
    if (values_->data() != data_ || values_->capacity() != capacity_) {
      std::abort();
    }
    secure_wipe_vector(*values_);
  }

 private:
  void require_remaining(size_t count) const {
    if (!can_append(count)) {
      std::abort();
    }
  }

  std::vector<T>* values_;
  T* data_;
  size_t capacity_;
};

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_UTIL_SECURE_WIPE_H_
