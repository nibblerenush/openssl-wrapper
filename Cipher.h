#pragma once

#include "BaseFunctions.h"

#include <memory>
#include <openssl/evp.h>

namespace openssl_wrapper
{
  class Cipher
  {
  public:
    Cipher(const std::string & cipherName);
    void SetPlaintext(const bytes_t & plaintext);
    bytes_t GetPlaintext() const;
    void SetCiphertext(const bytes_t & ciphertext);
    bytes_t GetCiphertext() const;
    void SetKey(const bytes_t & key);
    void SetIv(const bytes_t & iv);
    //
    void StartEncrypt();
    void Encrypt();
    void FinalEncrypt();
    //
    void StartDecrypt();
    void Decrypt();
    void FinalDecrypt();
    //
    static bytes_t Encrypt(const std::string & cipherName, const bytes_t & key, const bytes_t & iv, const bytes_t & plaintext);
    static bytes_t Decrypt(const std::string & cipherName, const bytes_t & key, const bytes_t & iv, const bytes_t & ciphertext);
  private:
    static void ContextDeleter(EVP_CIPHER_CTX * context);
  private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&ContextDeleter)> _context;
    std::string _cipherName;
    bytes_t _plaintext;
    bytes_t _ciphertext;
    bytes_t _key;
    bytes_t _iv;
  };
}
