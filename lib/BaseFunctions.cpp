#include "BaseFunctions.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <memory>
#include <sstream>

#include <openssl/err.h>

namespace openssl_wrapper
{
  // from 'man ERR_error_string'
  static const unsigned int ERROR_BUFFER_SIZE = 120;
  
  std::string GetSslErrorString()
  {
    char errBuf[ERROR_BUFFER_SIZE];
    ERR_error_string_n(ERR_get_error(), errBuf, sizeof(errBuf));
    return errBuf;
  }
  
  std::string GetOsErrorString() {
    return std::strerror(errno);
  }
  
  bytes_t GetFileData(const std::string & filename)
  {
    //
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);
    
    //
    ThrowSystemError(std::fseek(file.get(), 0, SEEK_END), -1, Operation::EQUAL);
    
    //
    long size = std::ftell(file.get());
    ThrowSystemError(size, -1L, Operation::EQUAL);
    
    //
    ThrowSystemError(std::fseek(file.get(), 0, SEEK_SET), -1, Operation::EQUAL);
    
    //
    bytes_t result(size);
    ThrowSystemError(std::fread(result.data(), 1, size, file.get()), static_cast<std::size_t>(size), Operation::NOT_EQUAL);
    return result;
  }
  
  void WriteToFile(const std::string & filename, const bytes_t & outData)
  {
    //
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);
    
    //
    std::size_t size = outData.size();
    ThrowSystemError(std::fwrite(outData.data(), 1, outData.size(), file.get()), size, Operation::NOT_EQUAL);
  }
  
  std::string GetHexString(const bytes_t & bytes)
  {
    std::ostringstream result;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
      result << std::hex << static_cast<int>(bytes[i]);
    }
    return result.str();
  }
  
  std::string GetAsciiString(const bytes_t & bytes)
  {
    if (std::any_of(bytes.begin(), bytes.end(), [] (std::uint8_t byte) { return byte > 127; })) {
      throw std::invalid_argument("Invalid ascii string");
    }
    
    std::string result;
    std::copy(bytes.begin(), bytes.end(), std::back_inserter(result));
    return result;
  }
}
