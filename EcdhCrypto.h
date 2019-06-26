#pragma once

#include "KeyAgreement.h"
#include <openssl/ec.h>

namespace openssl_wrapper
{
  class EcdhCrypto: public KeyAgreement
  {
  public:
    EcdhCrypto();
    void SetEllipticCurve(int ellipticCurve);
    void GenerateParameters() override;
    void KeyExchange(const EcdhCrypto & peerDhCrypto);
  private:
    int _ellipticCurve;
  };
}

