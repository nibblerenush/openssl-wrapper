#include "Hmac.h"

#include <memory>
#include <new>

namespace openssl_wrapper
{
  bytes_t Hmac::GetMac(const std::string & digestname, const bytes_t & msg, const bytes_t & key)
  {
    // 1 step
    auto hmacCtx = std::unique_ptr<HMAC_CTX, decltype(&ContextDeleter)>(new (std::nothrow) HMAC_CTX, &ContextDeleter);
    if (!hmacCtx)
    {
      throw WrapperException("Hmac allocating error", __FILE__, __LINE__);
    }
    HMAC_CTX_init(hmacCtx.get());
    // 2 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType)
    {
      throw WrapperException("Invalid digest name", __FILE__, __LINE__);
    }
    // 3 step
    if (!HMAC_Init_ex(hmacCtx.get(), key.data(), key.size(), digestType, nullptr))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (!HMAC_Update(hmacCtx.get(), msg.data(), msg.size()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    unsigned int hmacSize = 0;
    bytes_t result(EVP_MAX_MD_SIZE);
    if (!HMAC_Final(hmacCtx.get(), result.data(), &hmacSize))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    result.resize(hmacSize);
    return result;
  }
  
  void Hmac::ContextDeleter(HMAC_CTX * context)
  {
    HMAC_CTX_cleanup(context);
    delete context;
  }
}
