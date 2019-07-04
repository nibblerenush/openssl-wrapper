#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "BaseFunctions.h"
#include "Digest.h"

using namespace openssl_wrapper;

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  try
  {
    auto data = BaseFunctions::GetFileData("msg.txt");
    auto hash = Digest::GetHash("SHA1", data);
    std::cout << BaseFunctions::GetByteString(hash) << std::endl;
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
