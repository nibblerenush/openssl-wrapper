#pragma once

#include <memory>
#include <openssl/evp.h>

namespace openssl_wrapper
{
  class Parameters
  {
  public:
    Parameters();
    virtual void GenerateParameters() = 0;
    // ===== Write/Read =====
    virtual void WriteParametersToFile(const std::string & filename) = 0;
    virtual void ReadParametersFromFile(const std::string & filename) = 0;
    // ===== Write/Read =====
  protected:
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> _params;
    friend class Key;
  };
}
