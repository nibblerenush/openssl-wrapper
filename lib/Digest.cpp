#include "Digest.h"

#include <memory>
#include <openssl/evp.h>

namespace openssl_wrapper
{
  bytes_t Digest::GetHash(const std::string & digestname, const bytes_t & data)
  {
    // 1 step
    auto digestCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    if (!digestCtx)
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
    if (!EVP_DigestInit_ex(digestCtx.get(), digestType, nullptr))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (!EVP_DigestUpdate(digestCtx.get(), data.data(), data.size()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    unsigned int digestSize = 0;
    bytes_t result(EVP_MD_size(digestType));
    if (!EVP_DigestFinal_ex(digestCtx.get(), result.data(), &digestSize))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    return result;
  }
}
