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
    void WriteParametersToFile(const std::string & filename) const override;
    void ReadParametersFromFile(const std::string & filename) override;
    // ===== Write/Read =====
  private:
    int m_primeLen;
    int m_generator;
  };
}
