#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <memory>

#include "Cipher.h"
#include "BaseFunctions.h"

#include <openssl/dh.h>

#include "RsaCrypto.h"
#include "DhCrypto.h"

int main()
{
  
 OpenSSL_add_all_algorithms();
 ERR_load_crypto_strings();
 
 try
 {
   /*openssl_wrapper::Cipher cipher("des-cbc");
   std::vector<uint8_t> data = openssl_wrapper::BaseFunctions::GetFileData("output.bin");
   
    std::vector<uint8_t> result = openssl_wrapper::Cipher::Decrypt("des-cbc", {0, 1, 2, 3, 4, 5, 6, 7}, {0, 1, 2, 3, 4, 5, 6, 7}, data);*/
   
   /*cipher.SetKey({0, 1, 2, 3, 4, 5, 6, 7});
   cipher.SetIv({0, 1, 2, 3, 4, 5, 6, 7});
   cipher.SetCiphertext(data);
   
   cipher.StartDecrypt();
   cipher.Decrypt();
   cipher.FinalDecrypt();*/
   
   //std::cout << (char*)result.data() << std::endl;
   
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
   
   /*openssl_wrapper::RsaCrypto rsaCrypto;
   rsaCrypto.GenerateKey();
   rsaCrypto.WritePrivateKeyToFile("private.pem", "aes-128-cbc", "12345");
   rsaCrypto.WritePublicKeyToFile("public.pem");
   rsaCrypto.SetPlaintext({'H', 'E', 'L', 'L', '\n'});
   rsaCrypto.Encrypt();*/
   
   /*openssl_wrapper::DhCrypto dhCrypto;
   dhCrypto.GenerateParameters();
   dhCrypto.WriteParametersToFile("parameters.pem");
   dhCrypto.GenerateKey();
   dhCrypto.WritePublicKeyToFile("dhkeypublic.pem");
   dhCrypto.WritePrivateKeyToFile("dhkeprivate.pem", "aes-128-cbc", "qwerty");*/
   
   /*rsaCrypto.ReadPrivateKeyFromFile("private.pem", "12345");
   auto fileData = openssl_wrapper::BaseFunctions::GetFileData("output.bin");
   rsaCrypto.SetCiphertext(fileData);
   rsaCrypto.Decrypt();
   std::cout << (char*)rsaCrypto.GetPlaintext().data();*/
   
   //openssl_wrapper::BaseFunctions::WriteToFile("output.bin", rsaCrypto.GetCiphertext());
   
   
   openssl_wrapper::DhCrypto dhc1;
   openssl_wrapper::DhCrypto dhc2;
   
   dhc1.GenerateParameters();
   dhc1.WriteParametersToFile("dhc1.pem");
   dhc1.GenerateKey();
   
   dhc2.ReadParametersFromFile("dhc1.pem");
   dhc2.GenerateKey();
   
   dhc1.KeyExchange(dhc2);
   dhc2.KeyExchange(dhc1);
   auto skey1 = dhc1.GetSharedSecret();
   auto skey2 = dhc2.GetSharedSecret();
   
   for (std::size_t i = 0; i < skey1.size(); ++i)
   {
     std::cout << std::hex << (int)skey1[i] << " " << (int)skey2[i] << " ";
   }
   std::cout << std::endl;
   
   //dhc2.WriteParametersToFile("dhc2.pem");
   
   /*dhc2.SetGenerator(dhc1.GetGenerator());
   dhc2.SetPrimeLen(dhc1.GetPrimeLen());
   dhc2.GenerateParameters();
   dhc2.GenerateKey();
   
   dhc1.KeyExchange(dhc2);*/
 }
 catch (openssl_wrapper::WrapperException ex)
 {
   std::cerr << ex.what() << std::endl;
   
 }
 
 

 
 std::cerr << "END\n";
 
 ERR_free_strings();
 EVP_cleanup();
 return EXIT_SUCCESS;
}
