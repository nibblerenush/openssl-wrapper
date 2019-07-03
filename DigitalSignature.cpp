#include "DigitalSignature.h"

namespace openssl_wrapper
{
  bytes_t DigitalSignature::Sign(const Key & key, const std::string & digestname, const bytes_t & msg)
  {
    // 1 step
    auto signCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    if (!signCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType)
    {
      throw WrapperException("Invalid digest name", __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_DigestSignInit(signCtx.get(), nullptr, digestType, nullptr, key._pkey.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (EVP_DigestSignUpdate(signCtx.get(), msg.data(), msg.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    std::size_t siglen = 0;
    if (EVP_DigestSignFinal(signCtx.get(), nullptr, &siglen) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    bytes_t signature(siglen);
    // 6 step
    if (EVP_DigestSignFinal(signCtx.get(), signature.data(), &siglen) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    signature.resize(siglen);
    return signature;
  }
  
  bool DigitalSignature::Verify(const Key & key, const std::string & digestname, const bytes_t & msg, const bytes_t & sign)
  {
    // 1 step
    auto verifyCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    if (!verifyCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType)
    {
      throw WrapperException("Invalid digest name", __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_DigestVerifyInit(verifyCtx.get(), nullptr, digestType, nullptr, key._pkey.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (EVP_DigestVerifyUpdate(verifyCtx.get(), msg.data(), msg.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    switch (EVP_DigestVerifyFinal(verifyCtx.get(), sign.data(), sign.size()))
    {
      case 1:
        return true;
      case 0:
        return false;
      default:
        throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
}
