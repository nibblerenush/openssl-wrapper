#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <memory>

#include "Cipher.h"
#include "BaseFunctions.h"

int main()
{
  
 OpenSSL_add_all_algorithms();
 ERR_load_crypto_strings();
 
 try
 {
   openssl_wrapper::Cipher cipher("des-cbc");
   std::vector<uint8_t> data = openssl_wrapper::BaseFunctions::GetFileData("output.bin");
   
    std::vector<uint8_t> result = openssl_wrapper::Cipher::Decrypt("des-cbc", {0, 1, 2, 3, 4, 5, 6, 7}, {0, 1, 2, 3, 4, 5, 6, 7}, data);
   
   /*cipher.SetKey({0, 1, 2, 3, 4, 5, 6, 7});
   cipher.SetIv({0, 1, 2, 3, 4, 5, 6, 7});
   cipher.SetCiphertext(data);
   
   cipher.StartDecrypt();
   cipher.Decrypt();
   cipher.FinalDecrypt();*/
   
   std::cout << (char*)result.data() << std::endl;
   
   /*FILE * out = fopen("output.bin", "wb");
   cipher.SetKey({0, 1, 2, 3, 4, 5, 6, 7});
   cipher.SetIv({0, 1, 2, 3, 4, 5, 6, 7});
   
   
   cipher.StartEncrypt();
   
   cipher.SetPlaintext({'H', 'E', 'L', 'L', 'H', 'E', 'L', 'L', '\n'});
   cipher.Encrypt();
   fwrite(cipher.GetCiphertext().data(), 1, cipher.GetCiphertext().size(), out);
   
   cipher.SetPlaintext({'H', 'U', 'B', 'B', 'H', 'E', 'L', 'L', '\n'});
   cipher.Encrypt();
   
   cipher.FinalEncrypt();
   
   fwrite(cipher.GetCiphertext().data(), 1, cipher.GetCiphertext().size(), out);
   fclose(out);*/
   
   /*out = fopen("output.bin", "wb");
   
   cipher.StartEncrypt();
   cipher.SetPlaintext({'H', 'E', 'L', 'L', 'H', 'E', 'L', 'L', '\n'});
   cipher.Encrypt();
   cipher.FinalEncrypt();
   
   
   fwrite(cipher.GetCiphertext().data(), 1, cipher.GetCiphertext().size(), out);
   fclose(out);*/
   
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
