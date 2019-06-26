#include "EcdhCrypto.h"

namespace openssl_wrapper
{
  EcdhCrypto::EcdhCrypto():
  KeyAgreement(),
  _ellipticCurve(NID_secp256k1)
  {}
  
  void EcdhCrypto::SetEllipticCurve(int ellipticCurve)
  {
    _ellipticCurve = ellipticCurve;
  }
  
  void EcdhCrypto::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
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
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsCtx.get(), _ellipticCurve) <= 0)
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
  
  void EcdhCrypto::KeyExchange(const EcdhCrypto & peerDhCrypto)
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
