#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "BaseFunctions.h"
#include "Digest.h"
#include "Hmac.h"

using namespace openssl_wrapper;

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  try
  {
    auto data = BaseFunctions::GetFileData("msg.txt");
    //auto result = Digest::GetHash("SHA1", data);
    auto result = Hmac::GetMac("SHA1", data, {'1', '2', '3', '4'});
    std::cout << BaseFunctions::GetByteString(result) << std::endl;
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
