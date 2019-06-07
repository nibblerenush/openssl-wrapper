#pragma once

#include <openssl/evp.h>

#include <cstdint>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace openssl_wrapper
{
  class CipherException: std::exception
  {
  public:
    CipherException(const std::string & info);
    const char * what() const noexcept override;
  private:
    std::string _info;
  };
  
  class Cipher
  {
  public:
    Cipher(const std::string & cipherName);
    void SetPlaintext(const std::vector<uint8_t> & plaintext);
    std::vector<uint8_t> GetPlaintext() const;
    void SetCiphertext(const std::vector<uint8_t> & ciphertext);
    std::vector<uint8_t> GetCiphertext() const;
    void SetKey(const std::vector<uint8_t> & key);
    void SetIv(const std::vector<uint8_t> & iv);
    void Encrypt();
    void Decrypt();
  private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_cleanup)> _context;
    std::vector<uint8_t> _plaintext;
    std::vector<uint8_t> _ciphertext;
    std::vector<uint8_t> _key;
    std::vector<uint8_t> _iv;
  };
}
