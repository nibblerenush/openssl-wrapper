#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "BaseFunctions.h"

using namespace openssl_wrapper;

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  try
  {
    // Some code
  }
  catch (WrapperException ex)
  {
    std::cerr << ex.what() << std::endl;
  }
  
  std::cerr << "END\n";
  ERR_free_strings();
  EVP_cleanup();
  return EXIT_SUCCESS;
}
