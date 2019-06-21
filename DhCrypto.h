#pragma once

#include "BaseFunctions.h"
#include <memory>

#include <openssl/evp.h>
#include <openssl/dh.h>

namespace openssl_wrapper
{
  class DhCrypto
  {
  public:
    DhCrypto();
    void SetPrimeLen(int primeLen);
    void SetGenerator(int generator);
    void GenerateParameters();
    void WriteParametersToFile(const std::string & filename);
    void GenerateKey();
    void WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass);
    void WritePublicKeyToFile(const std::string & filename);
    
  private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _params;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _pkey;
    int _primeLen;
    int _generator;
  };
}
