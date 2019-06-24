#pragma once

#include "BaseFunctions.h"
#include <memory>

#include <openssl/evp.h>
#include <openssl/rsa.h>

namespace openssl_wrapper
{
  enum class Padding
  {
    RSA_PKCS1 = RSA_PKCS1_PADDING,
    RSA_SSLV23 = RSA_SSLV23_PADDING,
    RSA_NO = RSA_NO_PADDING,
    RSA_PKCS1_OAEP = RSA_PKCS1_OAEP_PADDING,
    RSA_X931 = RSA_X931_PADDING,
    RSA_PKCS1_PSS = RSA_PKCS1_PSS_PADDING
  };
  
  class RsaCrypto
  {
  public:
    RsaCrypto();
    void SetKeygenBits(int keygenBits);
    void SetKeygenPubexp(int pubexp);
    void SetPadding(Padding padding);
    void GenerateKey();
    void WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass);
    void ReadPrivateKeyFromFile(const std::string & filename, const std::string & pass);
    void WritePublicKeyToFile(const std::string & filename);
    void ReadPublicKeyFromFile(const std::string & filename);
    void SetPlaintext(const bytes_t & plaintext);
    bytes_t GetPlaintext() const;
    void SetCiphertext(const bytes_t & ciphertext);
    bytes_t GetCiphertext() const;
    void Encrypt();
    void Decrypt();
  private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _pkey;
    int _keygenBits;
    int _pubexp;
    Padding _padding;
    bytes_t _plaintext;
    bytes_t _ciphertext;
  private:
    static const int DEFAULT_KEYGEN_BITS;
  };
}
