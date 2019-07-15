#include "params/Parameters.h"

namespace openssl_wrapper
{
  Parameters::Parameters():
  _params(nullptr, &EVP_PKEY_free)
  {}
}
