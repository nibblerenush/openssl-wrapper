#pragma once

#include "KeyAgreement.h"
#include <openssl/dh.h>

namespace openssl_wrapper
{
  class DhCrypto: public KeyAgreement
  {
  public:
    DhCrypto();
    void SetPrimeLen(int primeLen);
    void SetGenerator(int generator);
    void GenerateParameters() override;
    void WriteParametersToFile(const std::string & filename);
    void ReadParametersFromFile(const std::string & filename);
    void KeyExchange(const DhCrypto & peerDhCrypto);
  private:
    int _primeLen;
    int _generator;
  private:
    static const int DEFAULT_PRIME_LEN;
  };
}
