#include "params/DhParams.h"
#include "BaseFunctions.h"

#include <openssl/dh.h>
#include <openssl/pem.h>

namespace openssl_wrapper
{
  const int openssl_wrapper::DhParams::DEFAULT_PRIME_LEN = 1024;
  
  DhParams::DhParams():
  Parameters(),
  _primeLen(DEFAULT_PRIME_LEN),
  _generator(DH_GENERATOR_2)
  {}
  
  // ===== Set/Get =====
  void DhParams::SetPrimeLen(int primeLen)
  {
    _primeLen = primeLen;
  }
  int DhParams::GetPrimeLen() const
  {
    return _primeLen;
  }
  void DhParams::SetGenerator(int generator)
  {
    _generator = generator;
  }
  int DhParams::GetGenerator() const
  {
    return _generator;
  }
  // ===== Set/Get =====
  
  void DhParams::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr), &EVP_PKEY_CTX_free);
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
    if (EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramsCtx.get(), _primeLen) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (EVP_PKEY_CTX_set_dh_paramgen_generator(paramsCtx.get(), _generator) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    EVP_PKEY * tempParams = nullptr;
    if (EVP_PKEY_paramgen(paramsCtx.get(), &tempParams) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _params.reset(tempParams);
  }
  
  // ===== Write/Read =====
  void DhParams::WriteParametersToFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    DH * dh = EVP_PKEY_get1_DH(_params.get());
    if (!dh)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (!PEM_write_DHparams(file.get(), dh))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void DhParams::ReadParametersFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    DH * dh = PEM_read_DHparams(file.get(), nullptr, nullptr, nullptr);
    if (!dh)
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
    if (!EVP_PKEY_assign_DH(_params.get(), dh))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  // ===== Write/Read =====
}
