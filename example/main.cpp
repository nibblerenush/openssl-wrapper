#include <cstring>
#include <memory>
#include <iostream>

#include "params/DhParams.h"
#include "params/DsaParams.h"
#include "params/EcParams.h"
#include "params/Parameters.h"

#include "BaseFunctions.h"
#include "Cipher.h"
#include "Digest.h"
#include "DigitalSignature.h"
#include "Hmac.h"
#include "Initializer.h"
#include "Key.h"
#include "KeyAgreement.h"
#include "RsaKey.h"

using namespace openssl_wrapper;

int main(int argc, char ** argv)
{
  if (argc != 2)
  {
    std::cerr << "Usage: " << argv[0] << " <operation type>" << std::endl;
    return EXIT_FAILURE;
  }

  Initialize();
  
  try
  {
    bytes_t plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};

    // Symmetric encryption
    if (std::strcmp(argv[1], "Cipher") == 0)
    {
      Cipher cipher("aes-128-cbc");
      cipher.SetKey({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
      cipher.SetIv({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
      cipher.SetPlaintext(plaintext);
      
      cipher.StartEncrypt();
      cipher.Encrypt();
      cipher.FinalEncrypt();
      
      std::cout << "plaintext: " << GetAsciiString(plaintext) << '\n'
        << "ciphertext: " << GetHexString(cipher.GetCiphertext()) << std::endl;
    }

    // Diffie Hellman
    else if (std::strcmp(argv[1], "KeyAgreement") == 0)
    {
      std::unique_ptr<Parameters> dhParams(new DhParams());
      dhParams->GenerateParameters();
      dhParams->WriteParametersToFile("DhParams.pem");

      std::unique_ptr<Parameters> ecParams(new EcParams());
      ecParams->GenerateParameters();
      ecParams->WriteParametersToFile("EcParams.pem");

      Key dhKey1;
      dhKey1.GenerateKey(dhParams.get());
      dhKey1.WritePrivateKeyToFile("dhKey1.pem", "aes-128-cbc", "1234");

      Key dhKey2;
      dhKey2.GenerateKey(dhParams.get());
      dhKey2.WritePrivateKeyToFile("dhKey2.pem", "aes-128-cbc", "1234");

      Key ecKey1;
      ecKey1.GenerateKey(ecParams.get());
      ecKey1.WritePrivateKeyToFile("ecKey1.pem", "aes-128-cbc", "1234");

      Key ecKey2;
      ecKey2.GenerateKey(ecParams.get());
      ecKey2.WritePrivateKeyToFile("ecKey2.pem", "aes-128-cbc", "1234");

      bytes_t dhKeyAgreement = KeyAgreement::KeyExchange(dhKey1, dhKey2);
      bytes_t ecKeyAgreement = KeyAgreement::KeyExchange(ecKey1, ecKey2);

      std::cout << "DH common key: " << GetHexString(dhKeyAgreement) << '\n'
        << "EC common key: " << GetHexString(ecKeyAgreement) << std::endl;
    }

    // RSA encryption
    else if (std::strcmp(argv[1], "RsaEncrypt") == 0)
    {
      RsaKey rsaKey;
      rsaKey.GenerateKey();
      rsaKey.WritePrivateKeyToFile("rsaEncryptKey.pem", "aes-128-cbc", "1234");

      rsaKey.SetPlaintext(plaintext);
      rsaKey.Encrypt();
      
      std::cout << "plaintext: " << GetAsciiString(plaintext) << '\n'
        << "ciphertext: " << GetHexString(rsaKey.GetCiphertext()) << std::endl;
    }

    // Digital signature
    else if (std::strcmp(argv[1], "DigitalSignature") == 0)
    {
      RsaKey rsaKey;
      rsaKey.GenerateKey();
      rsaKey.WritePrivateKeyToFile("rsaSignKey.pem", "aes-128-cbc", "1234");

      std::unique_ptr<Parameters> dsaParams(new DsaParams);
      dsaParams->GenerateParameters();
      dsaParams->WriteParametersToFile("DsaParams.pem");

      std::unique_ptr<Parameters> ecParams(new EcParams);
      ecParams->GenerateParameters();
      ecParams->WriteParametersToFile("EcParams.pem");

      Key dsaKey;
      dsaKey.GenerateKey(dsaParams.get());
      dsaKey.WritePrivateKeyToFile("dsaKey.pem", "aes-128-cbc", "1234");

      Key ecKey;
      ecKey.GenerateKey(ecParams.get());
      ecKey.WritePrivateKeyToFile("ecKey.pem", "aes-128-cbc", "1234");

      bytes_t rsaSignature = DigitalSignature::Sign(rsaKey, "SHA256", plaintext);
      bytes_t dsaSignature = DigitalSignature::Sign(dsaKey, "SHA256", plaintext);
      bytes_t ecdsaSignature = DigitalSignature::Sign(ecKey, "SHA256", plaintext);

      std::cout << "RSA signature: " << GetHexString(rsaSignature) << '\n'
        << "Dsa signature: " << GetHexString(dsaSignature) << '\n'
        << "Ecdsa signature: " << GetHexString(ecdsaSignature) << std::endl;
    }

    // Digest
    else if (std::strcmp(argv[1], "Digest") == 0)
    {
      bytes_t digest = Digest::GetHash("SHA1", plaintext);

      std::cout << "plaintext: " << GetAsciiString(plaintext) << '\n'
        << "digest: " << GetHexString(digest) << std::endl;
    }

    // Hmac
    else if (std::strcmp(argv[1], "Hmac") == 0)
    {
      bytes_t hmac = Hmac::GetMac("SHA1", plaintext, {'1', '2', '3', '4'});
      
      std::cout << "plaintext: " << GetAsciiString(plaintext) << '\n'
        << "hmac: " << GetHexString(hmac) << std::endl;
    }

    // Invalid
    else
    {
      std::cerr << "Invalid operation type!" << std::endl;
      return EXIT_FAILURE;
    }
  }
  catch (const std::exception & ex)
  {
    std::cerr << "Error: " << ex.what() << std::endl;
    return EXIT_FAILURE;
  }
  
  return EXIT_SUCCESS;
}
