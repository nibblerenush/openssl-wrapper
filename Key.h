#pragma once

#include <memory>
#include <openssl/evp.h>

#include "params/Parameters.h"

namespace openssl_wrapper
{
  class Key
  {
  public:
    Key();
    virtual void GenerateKey(const Parameters * params = nullptr);
    // ===== Write/Read =====
    void WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass);
    void ReadPrivateKeyFromFile(const std::string & filename, const std::string & pass);
    void WritePublicKeyToFile(const std::string & filename);
    void ReadPublicKeyFromFile(const std::string & filename);
    // ===== Write/Read =====
  private:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _pkey;
    friend class KeyAgreement;
    friend class DigitalSignature;
  };
}
