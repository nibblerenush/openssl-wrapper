#include "Hmac.h"

#include <memory>
#include <new>

namespace openssl_wrapper
{
  bytes_t Hmac::GetMac(const std::string & digestname, const bytes_t & msg, const bytes_t & key)
  {
    // 1 step
    const EVP_MD * digestType = EVP_get_digestbyname(digestname.c_str());
    if (!digestType) {
      throw std::invalid_argument("Invalid digest name");
    }
    
    // 2 step
    auto hmacCtx = std::unique_ptr<HMAC_CTX, decltype(&ContextDeleter)>(new (std::nothrow) HMAC_CTX, &ContextDeleter);
    ThrowSslError<decltype(hmacCtx.get())>(hmacCtx.get(), nullptr, Operation::EQUAL);

    // 3 step
    HMAC_CTX_init(hmacCtx.get());
    
    // 4 step
    ThrowSslError(HMAC_Init_ex(hmacCtx.get(), key.data(), key.size(), digestType, nullptr), 0, Operation::EQUAL);

    // 5 step
    ThrowSslError(HMAC_Update(hmacCtx.get(), msg.data(), msg.size()), 0, Operation::EQUAL);

    // 6 step
    unsigned int hmacSize = 0;
    bytes_t result(EVP_MAX_MD_SIZE);
    ThrowSslError(HMAC_Final(hmacCtx.get(), result.data(), &hmacSize), 0, Operation::EQUAL);
    result.resize(hmacSize);
    
    return result;
  }
  
  void Hmac::ContextDeleter(HMAC_CTX * context)
  {
    HMAC_CTX_cleanup(context);
    delete context;
  }
}
