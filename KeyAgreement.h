#pragma once

#include "BaseFunctions.h"
#include <memory>

#include <openssl/evp.h>

namespace openssl_wrapper
{
  class KeyAgreement
  {
  public:
    KeyAgreement();
    virtual void GenerateParameters() = 0;
    void GenerateKey();
    void WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass);
    void ReadPrivateKeyFromFile(const std::string & filename, const std::string & pass);
    void WritePublicKeyToFile(const std::string & filename);
    void ReadPublicKeyFromFile(const std::string & filename);
    bytes_t GetSharedSecret() const;
  protected:
    void KeyExchange(const KeyAgreement & peerKey);
  protected:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _params;
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _pkey;
  private:
    bytes_t _sharedSecret;
  };
}
