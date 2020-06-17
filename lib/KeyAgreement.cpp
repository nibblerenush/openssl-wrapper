#include "KeyAgreement.h"

namespace openssl_wrapper
{
  bytes_t KeyAgreement::KeyExchange(const Key & key, const Key & peerKey)
  {
    // 1 step
    auto keyExchangeCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(key.m_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(keyExchangeCtx.get())>(keyExchangeCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_derive_init(keyExchangeCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_derive_set_peer(keyExchangeCtx.get(), peerKey.m_pkey.get()), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    std::size_t skeylen = 0;
    ThrowSslError(EVP_PKEY_derive(keyExchangeCtx.get(), nullptr, &skeylen), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    bytes_t sharedSecret(skeylen);
    ThrowSslError(EVP_PKEY_derive(keyExchangeCtx.get(), sharedSecret.data(), &skeylen), 0, Operation::LESS_OR_EQUAL);
    sharedSecret.resize(skeylen);
    return sharedSecret;
  }
}
