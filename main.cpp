#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <memory>

#include "Cipher.h"

int main()
{
  
 OpenSSL_add_all_algorithms();
 ERR_load_crypto_strings();
 
 try
 {
   openssl_wrapper::Cipher cipher("des-ecb");
   cipher.SetPlaintext({'H', 'E', 'L', 'L', 'H', 'E', 'L', 'L', 'H', 'E', 'L', 'L', '\n'});
   cipher.SetKey({0, 1, 2, 3, 4, 5, 6, 7});
   cipher.Encrypt();
   
   FILE * out = fopen("output.bin", "wb");
   fwrite(cipher.GetCiphertext().data(), 1, cipher.GetCiphertext().size(), out);
   fclose(out);
 }
 catch (openssl_wrapper::CipherException ex)
 {
   std::cerr << ex.what() << std::endl;
}
 
 

 
 std::cerr << "HER\n";
 
 ERR_free_strings();
 EVP_cleanup();
 return EXIT_SUCCESS;
}
