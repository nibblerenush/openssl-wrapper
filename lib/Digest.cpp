#include "Digest.h"

#include <memory>
#include <openssl/evp.h>

namespace openssl_wrapper
{
  bytes_t Digest::GetHash(const std::string & digestname, const bytes_t & data)
  {
    // 1 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType) {
      throw std::invalid_argument("Invalid digest name");
    }

    // 2 step
    auto digestCtx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_destroy)>(EVP_MD_CTX_create(), &EVP_MD_CTX_destroy);
    ThrowSslError<decltype(digestCtx.get())>(digestCtx.get(), nullptr, Operation::EQUAL);
    
    // 3 step
    ThrowSslError(EVP_DigestInit_ex(digestCtx.get(), digestType, nullptr), 0, Operation::EQUAL);

    // 4 step
    ThrowSslError(EVP_DigestUpdate(digestCtx.get(), data.data(), data.size()), 0, Operation::EQUAL);

    // 5 step
    unsigned int digestSize = 0;
    bytes_t result(EVP_MD_size(digestType));
    ThrowSslError(EVP_DigestFinal_ex(digestCtx.get(), result.data(), &digestSize), 0, Operation::EQUAL);
    return result;
  }
}
