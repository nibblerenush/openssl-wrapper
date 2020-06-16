#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>
#include <vector>

namespace openssl_wrapper
{
  using bytes_t = std::vector<std::uint8_t>;
  
  std::string GetSslErrorString();
  std::string GetSystemErrorString();
  
  enum class Operation
  {
    EQUAL,
    NOT_EQUAL,
    LESS,
    LESS_OR_EQUAL,
    MORE,
    MORE_OR_EQUAL
  };
  
  template<typename T>
  bool Compare(T lhs, T rhs, Operation op)
  {
    switch (op)
    {
      case Operation::EQUAL:
        return lhs == rhs;
      case Operation::NOT_EQUAL:
        return lhs != rhs;
      case Operation::LESS:
        return lhs < rhs;
      case Operation::LESS_OR_EQUAL:
        return lhs <= rhs;
      case Operation::MORE:
        return lhs > rhs;
      case Operation::MORE_OR_EQUAL:
        return lhs >= rhs;
      default:
        return true;
    }
  }
  
  template <typename T>
  void ThrowSslError(T lhs, T rhs, Operation op)
  {
    if (Compare(lhs, rhs, op)) {
      throw std::runtime_error(GetSslErrorString());
    }
  }

  template <typename T>
  void ThrowSystemError(T lhs, T rhs, Operation op)
  {
    if (Compare(lhs, rhs, op)) {
      throw std::runtime_error(GetSystemErrorString());
    }
  }
  
  bytes_t GetFileData(const std::string & filename);
  void WriteToFile(const std::string & filename, const bytes_t & outData);
  std::string GetHexString(const bytes_t & bytes);
  std::string GetAsciiString(const bytes_t & bytes);
}
