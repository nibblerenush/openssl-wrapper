#pragma once

#include "Parameters.h"

namespace openssl_wrapper
{
  class DhParams: public Parameters
  {
  public:
    DhParams();
    // ===== Set/Get =====
    void SetPrimeLen(int primeLen);
    int GetPrimeLen() const;
    void SetGenerator(int generator);
    int GetGenerator() const;
    // ===== Set/Get =====
    void GenerateParameters() override;
    // ===== Write/Read =====
    void WriteParametersToFile(const std::string & filename) override;
    void ReadParametersFromFile(const std::string & filename) override;
    // ===== Write/Read =====
  private:
    int _primeLen;
    int _generator;
  private:
    static const int DEFAULT_PRIME_LEN;
  };
}
