#pragma once

#include "BaseFunctions.h"

namespace openssl_wrapper
{
  class Digest
  {
  public:
    static bytes_t GetHash(const std::string & digestname, const bytes_t & data);
  };
}
