#pragma once

#include "BaseFunctions.h"
#include "Key.h"

namespace openssl_wrapper
{
  class DigitalSignature
  {
  public:
    static bytes_t Sign(const Key & key, const std::string & digestname, const bytes_t & msg);
    static bool Verify(const Key & key, const std::string & digestname, const bytes_t & msg, const bytes_t & sig);
  };
}
