#pragma once

#include <exception>
#include <cstdint>
#include <string>
#include <vector>

namespace openssl_wrapper
{
  using bytes = std::vector<uint8_t>;
  
  class WrapperException: std::exception
  {
  public:
    WrapperException(const std::string & info, const std::string & filename, int line);
    const char * what() const noexcept override;
  private:
    std::string _info;
  };
  
  class BaseFunctions
  {
  public:
    static std::string GetSslErrorString();
    static std::string GetOsErrorString();
    static bytes GetFileData(const std::string & filename);
    static void WriteToFile(const std::string & filename, const bytes & outData);
  private:
    static const unsigned int ERROR_BUFFER_SIZE;
  };
}
