#include "DhCrypto.h"

#include <openssl/pem.h>

namespace openssl_wrapper
{
  DhCrypto::DhCrypto():
  _params(nullptr, &EVP_PKEY_free),
  _pkey(nullptr, &EVP_PKEY_free),
  _primeLen(1024),
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
    if (!PEM_write_DHparams(file.get(), dh))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void DhCrypto::GenerateKey()
  {
    // 1 step
    auto keygenCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(_params.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!keygenCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_keygen_init(keygenCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    EVP_PKEY * tempPkey = nullptr;
    if (EVP_PKEY_keygen(keygenCtx.get(), &tempPkey) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  void DhCrypto::WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass)
  {
    if (pass.size() < 4)
    {
      throw WrapperException("Invalid pass size (must be >= 4)", __FILE__, __LINE__);
    }
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(cipherName.c_str());
    if (!evpCipher)
    {
      throw WrapperException("Invalid cipher name", __FILE__, __LINE__);
    }
    //
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    if (!PEM_write_PrivateKey(file.get(), _pkey.get(), evpCipher, (unsigned char*)pass.c_str(), pass.length(), nullptr, nullptr))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void DhCrypto::WritePublicKeyToFile(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    if (!PEM_write_PUBKEY(file.get(), _pkey.get()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
}
