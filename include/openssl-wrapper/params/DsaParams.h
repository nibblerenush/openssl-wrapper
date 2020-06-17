#pragma once

#include "Parameters.h"

namespace openssl_wrapper
{
  class DsaParams: public Parameters
  {
  public:
    DsaParams();
    // ===== Set/Get =====
    void SetNbits(int nbits);
    int GetNbits() const;
    // ===== Set/Get =====
    void GenerateParameters() override;
    // ===== Write/Read =====
    void WriteParametersToFile(const std::string & filename) const override;
    void ReadParametersFromFile(const std::string & filename) override;
    // ===== Write/Read =====
  private:
    int m_nbits;
  };
}
