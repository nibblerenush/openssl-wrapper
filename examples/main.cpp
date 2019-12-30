#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include "BaseFunctions.h"
#include "Initializer.h"
#include "Digest.h"
#include "Hmac.h"

using namespace openssl_wrapper;

int main()
{
  Initialize();
  
  try
  {
    auto data = BaseFunctions::GetFileData("msg.txt");
    //auto result = Digest::GetHash("SHA1", data);
    auto result = Hmac::GetMac("SHA1", data, {'1', '2', '3', '4'});
    std::cout << BaseFunctions::GetHexString(result) << std::endl;
  }
  catch (WrapperException ex)
  {
    std::cerr << ex.what() << std::endl;
  }
  
  std::cerr << "END\n";
  return EXIT_SUCCESS;
}
