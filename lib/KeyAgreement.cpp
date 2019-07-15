#include "KeyAgreement.h"

namespace openssl_wrapper
{
  bytes_t KeyAgreement::KeyExchange(const Key & key, const Key & peerKey)
  {
    // 1 step
    auto keyExchangeCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(key._pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!keyExchangeCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_derive_init(keyExchangeCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_derive_set_peer(keyExchangeCtx.get(), peerKey._pkey.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    std::size_t skeylen = 0;
    if (EVP_PKEY_derive(keyExchangeCtx.get(), nullptr, &skeylen) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    bytes_t sharedSecret(skeylen);
    // 5 step
    if (EVP_PKEY_derive(keyExchangeCtx.get(), sharedSecret.data(), &skeylen) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    sharedSecret.resize(skeylen);
    return sharedSecret;
  }
}
