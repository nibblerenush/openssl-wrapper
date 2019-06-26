#include "DhCrypto.h"

#include <openssl/pem.h>

namespace openssl_wrapper
{
  const int DhCrypto::DEFAULT_PRIME_LEN = 1024;
  
  DhCrypto::DhCrypto():
  KeyAgreement(),
  _primeLen(DEFAULT_PRIME_LEN),
  _generator(DH_GENERATOR_2)
  {}
  
  void DhCrypto::SetPrimeLen(int primeLen)
  {
    _primeLen = primeLen;
  }
  
  void DhCrypto::SetGenerator(int generator)
  {
    _generator = generator;
  }
  
  void DhCrypto::GenerateParameters()
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
    //
    if (EVP_PKEY_CTX_set_dh_paramgen_generator(paramsCtx.get(), _generator) <= 0)
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
  
  void DhCrypto::WriteParametersToFile(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    DH * dh = EVP_PKEY_get1_DH(_params.get());
    if (!dh)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    //
    if (!PEM_write_DHparams(file.get(), dh))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void DhCrypto::ReadParametersFromFile(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    DH * tempDh = PEM_read_DHparams(file.get(), nullptr, nullptr, nullptr);
    if (!tempDh)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    //
    _params.reset(EVP_PKEY_new());
    if (!_params)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    //
    if (!EVP_PKEY_assign_DH(_params.get(), tempDh))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void DhCrypto::KeyExchange(const DhCrypto & peerDhCrypto)
  {
    try
    {
      const KeyAgreement & peerKey = dynamic_cast<const KeyAgreement&>(peerDhCrypto);
      KeyAgreement::KeyExchange(peerKey);
    }
    catch (std::bad_cast ex)
    {
      throw WrapperException(ex.what(), __FILE__, __LINE__);
    }
  }
}
