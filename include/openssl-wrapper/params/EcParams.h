#pragma once

#include "Parameters.h"

namespace openssl_wrapper
{
  class EcParams: public Parameters
  {
  public:
    EcParams();
    // ===== Set/Get =====
    void SetEllipticCurve(int ellipticCurve);
    int GetEllipticCurve() const;
    // ===== Set/Get =====
    void GenerateParameters() override;
    // ===== Write/Read =====
    void WriteParametersToFile(const std::string & filename) const override;
    void ReadParametersFromFile(const std::string & filename) override;
    // ===== Write/Read =====
  private:
    int m_ellipticCurve;
  };
}
