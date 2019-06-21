#include "BaseFunctions.h"

#include <cstring>
#include <memory>

#include <openssl/err.h>

namespace openssl_wrapper
{
  WrapperException::WrapperException(const std::string & info, const std::string & filename, int line):
  std::exception(),
  _info(info + "; FILE: " + filename + "; LINE: " + std::to_string(line))
  {}
  
  const char * WrapperException::what() const noexcept
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
  
  bytes_t BaseFunctions::GetFileData(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    if (std::fseek(file.get(), 0, SEEK_END) == -1)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
    long size = std::ftell(file.get());
    if (size == -1)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
    if (std::fseek(file.get(), 0, SEEK_SET) == -1)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    bytes_t result(size);
    if (std::fread(result.data(), 1, size, file.get()) != size)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
    return result;
  }
  
  void BaseFunctions::WriteToFile(const std::string & filename, const bytes_t & outData)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    std::size_t size = outData.size();
    if (std::fwrite(outData.data(), 1, outData.size(), file.get()) != size)
    {
      throw WrapperException(GetOsErrorString(), __FILE__, __LINE__);
    }
  }
}
