#include <cstring>
#include <iostream>

#include "BaseFunctions.h"
#include "Initializer.h"
#include "Digest.h"
#include "Hmac.h"

#include "Cipher.h"

using namespace openssl_wrapper;

int main(int argc, char ** argv)
{
  if (argc != 2)
  {
    std::cerr << "Usage: " << argv[0] << " <type of example>" << std::endl;
    return EXIT_FAILURE;
  }

  Initialize();
  
  try
  {
    bytes_t plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

    if (std::strcmp(argv[1], "Cipher") == 0)
    {
      Cipher cipher("aes-128-cbc");
      cipher.SetKey({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
      cipher.SetIv({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
      cipher.SetPlaintext(plaintext);
      
      cipher.StartEncrypt();
      cipher.Encrypt();
      cipher.FinalEncrypt();
      
      std::cout << "plaintext: " << BaseFunctions::GetAsciiString(plaintext) << '\n'
        << "ciphertext: " << BaseFunctions::GetHexString(cipher.GetCiphertext()) << std::endl;
    }

    //auto data = BaseFunctions::GetFileData("msg.txt");
    //auto result = Digest::GetHash("SHA1", data);
    /*auto result = Hmac::GetMac("SHA1", data, {'1', '2', '3', '4'});
    std::cout << BaseFunctions::GetHexString(result) << std::endl;*/
  }
  catch (const WrapperException & ex)
  {
    std::cerr << "Error: " << ex.what() << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
