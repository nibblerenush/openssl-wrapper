#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <memory>

#include "Cipher.h"
#include "BaseFunctions.h"

#include "params/DhParams.h"
#include "params/EcParams.h"
#include "params/DsaParams.h"

#include "KeyAgreement.h"
#include "Key.h"

using namespace openssl_wrapper;

int main()
{
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  
  try
  {
    EcParams ec1;
    EcParams ec2;
    
    ec1.SetEllipticCurve(NID_secp256k1);
    ec2.SetEllipticCurve(NID_secp256k1);
    
    ec1.GenerateParameters();
    ec2.GenerateParameters();
    
    
    DhParams dh1;
    DhParams dh2;
    
    dh1.SetPrimeLen(1024);
    dh1.SetGenerator(2);
    dh1.GenerateParameters();
    
    dh1.WriteParametersToFile("temp.pem");
    dh2.ReadParametersFromFile("temp.pem");
    
    Key key1;
    key1.GenerateKey(&dh1);
    
    Key key2;
    key2.GenerateKey(&dh2);
    
    auto secret = KeyAgreement::KeyExchange(key1, key2);
    std::cerr << BaseFunctions::GetByteString(secret) << std::endl;
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
