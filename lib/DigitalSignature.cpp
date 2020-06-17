#include "DigitalSignature.h"

namespace openssl_wrapper
{
  bytes_t DigitalSignature::Sign(const Key & key, const std::string & digestname, const bytes_t & msg)
  {
    // 1 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType) {
      throw std::invalid_argument("Invalid digest name");
    }
    
    // 2 step
    auto signCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    ThrowSslError<decltype(signCtx.get())>(signCtx.get(), nullptr, Operation::EQUAL);

    // 3 step
    ThrowSslError(EVP_DigestSignInit(signCtx.get(), nullptr, digestType, nullptr, key.m_pkey.get()), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    ThrowSslError(EVP_DigestSignUpdate(signCtx.get(), msg.data(), msg.size()), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    std::size_t siglen = 0;
    ThrowSslError(EVP_DigestSignFinal(signCtx.get(), nullptr, &siglen), 0, Operation::LESS_OR_EQUAL);

    // 6 step
    bytes_t signature(siglen);
    ThrowSslError(EVP_DigestSignFinal(signCtx.get(), signature.data(), &siglen), 0, Operation::LESS_OR_EQUAL);
    signature.resize(siglen);
    return signature;
  }
  
  bool DigitalSignature::Verify(const Key & key, const std::string & digestname, const bytes_t & msg, const bytes_t & sign)
  {
    // 1 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType) {
      throw std::invalid_argument("Invalid digest name");
    }
    
    // 2 step
    auto verifyCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    ThrowSslError<decltype(verifyCtx.get())>(verifyCtx.get(), nullptr, Operation::EQUAL);
    
    // 3 step
    ThrowSslError(EVP_DigestVerifyInit(verifyCtx.get(), nullptr, digestType, nullptr, key.m_pkey.get()), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    ThrowSslError(EVP_DigestVerifyUpdate(verifyCtx.get(), msg.data(), msg.size()), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    switch (EVP_DigestVerifyFinal(verifyCtx.get(), sign.data(), sign.size()))
    {
      case 1:
        return true;
      case 0:
        return false;
      default:
        ThrowSslError(0, 0, Operation::EQUAL);
    }
  }
}
