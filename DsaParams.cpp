#include "DsaParams.h"
#include "BaseFunctions.h"

#include <openssl/dsa.h>
#include <openssl/pem.h>

namespace openssl_wrapper
{
  const int DsaParams::DEFAULT_NBITS = 1024;
  
  DsaParams::DsaParams():
  Parameters(),
  _nbits(DEFAULT_NBITS)
  {}
  
  // ===== Set/Get =====
  void DsaParams::SetNbits(int nbits)
  {
    _nbits = nbits;
  }
  
  int DsaParams::GetNbits() const
  {
    return _nbits;
  }
  // ===== Set/Get =====
  
  void DsaParams::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr), &EVP_PKEY_CTX_free);
    if (!paramsCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_paramgen_init(paramsCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_CTX_set_dsa_paramgen_bits(paramsCtx.get(), _nbits) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    EVP_PKEY * tempParams = nullptr;
    if (EVP_PKEY_paramgen(paramsCtx.get(), &tempParams) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _params.reset(tempParams);
  }
  
  // ===== Write/Read =====
  void DsaParams::WriteParametersToFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    DSA * dsa = EVP_PKEY_get1_DSA(_params.get());
    if (!dsa)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (!PEM_write_DSAparams(file.get(), dsa))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void DsaParams::ReadParametersFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    DSA * dsa = PEM_read_DSAparams(file.get(), nullptr, nullptr, nullptr);
    if (!dsa)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    _params.reset(EVP_PKEY_new());
    if (!_params)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (!EVP_PKEY_assign_DSA(_params.get(), dsa))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  // ===== Write/Read =====
}
