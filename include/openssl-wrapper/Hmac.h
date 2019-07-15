#pragma once

#include "BaseFunctions.h"
#include <openssl/hmac.h>

namespace openssl_wrapper
{
  class Hmac
  {
  public:
    static bytes_t GetMac(const std::string & digestname, const bytes_t & msg, const bytes_t & key);
  private:
    static void ContextDeleter(HMAC_CTX * context);
  };
}
