#pragma once

#include <exception>
#include <string>
#include <vector>

namespace openssl_wrapper
{
  class BaseException: std::exception
  {
  public:
    BaseException(const std::string & info);
    const char * what() const noexcept override;
  private:
    std::string _info;
  };
  
  class BaseFunctions
  {
  public:
    static std::string GetSslErrorString();
    static std::string GetOsErrorString();
    static std::vector<uint8_t> GetFileData(const std::string & filename);
  private:
    static const unsigned int ERROR_BUFFER_SIZE;
  };
}
