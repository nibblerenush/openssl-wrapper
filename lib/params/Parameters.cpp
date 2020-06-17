#include "params/Parameters.h"

namespace openssl_wrapper
{
  Parameters::Parameters(): m_params(nullptr, &EVP_PKEY_free)
  {}
}
