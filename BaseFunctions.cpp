#include "BaseFunctions.h"

#include <openssl/err.h>

#include <cstring>
#include <memory>

namespace openssl_wrapper
{
  BaseException::BaseException(const std::string & info):
  std::exception(),
  _info(info)
  {}
  
  const char * BaseException::what() const noexcept
  {
    return _info.c_str();
  }
  
  const unsigned int BaseFunctions::ERROR_BUFFER_SIZE = 120;
  
  std::string BaseFunctions::GetSslErrorString()
  {
    char errBuf[ERROR_BUFFER_SIZE];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    return errBuf;
  }
  
  std::string BaseFunctions::GetOsErrorString()
  {
    return std::strerror(errno);
  }
  
  std::vector<uint8_t> BaseFunctions::GetFileData(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw BaseException(GetOsErrorString());
    }
    
    if (std::fseek(file.get(), 0, SEEK_END) == -1)
    {
      throw BaseException(GetOsErrorString());
    }
    long size = std::ftell(file.get());
    if (size == -1)
    {
      throw BaseException(GetOsErrorString());
    }
    if (std::fseek(file.get(), 0, SEEK_SET) == -1)
    {
      throw BaseException(GetOsErrorString());
    }
    
    std::vector<uint8_t> result(size);
    if (std::fread(result.data(), size, 1, file.get()) == 0)
    {
      throw BaseException(GetOsErrorString());
    }
    return result;
  }
}
