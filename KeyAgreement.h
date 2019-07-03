#pragma once

#include "BaseFunctions.h"
#include "Key.h"

namespace openssl_wrapper
{
  class KeyAgreement
  {
  public:
    static bytes_t KeyExchange(const Key & key, const Key & peerKey);
  };
}
