#pragma once

#include <openssl/evp.h>

#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <vector>

namespace openssl_wrapper
{
  using bytes = std::vector<uint8_t>;
  
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
    void SetPlaintext(const bytes & plaintext);
    bytes GetPlaintext() const;
    void SetCiphertext(const bytes & ciphertext);
    bytes GetCiphertext() const;
    void SetKey(const bytes & key);
    void SetIv(const bytes & iv);
    //
    void StartEncrypt();
    void Encrypt();
    void FinalEncrypt();
    //
    void StartDecrypt();
    void Decrypt();
    void FinalDecrypt();
    //
    static bytes Encrypt(const std::string & cipherName, const bytes & key, const bytes & iv, const bytes & plaintext);
    static bytes Decrypt(const std::string & cipherName, const bytes & key, const bytes & iv, const bytes & ciphertext);
  private:
    static void ContextDeleter(EVP_CIPHER_CTX * context);
  private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&ContextDeleter)> _context;
    std::string _cipherName;
    bytes _plaintext;
    bytes _ciphertext;
    bytes _key;
    bytes _iv;
  };
}
