#include "params/EcParams.h"
#include "BaseFunctions.h"

#include <openssl/ec.h>
#include <openssl/pem.h>

namespace openssl_wrapper
{
  EcParams::EcParams(): Parameters(), m_ellipticCurve(NID_X9_62_prime256v1)
  {}
  
  // ===== Set/Get =====
  void EcParams::SetEllipticCurve(int ellipticCurve) {
    m_ellipticCurve = ellipticCurve;
  }

  int EcParams::GetEllipticCurve() const {
    return m_ellipticCurve;
  }
  // ===== Set/Get =====
  
  void EcParams::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(paramsCtx.get())>(paramsCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_paramgen_init(paramsCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsCtx.get(), m_ellipticCurve), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    EVP_PKEY * tempParams = nullptr;
    ThrowSslError(EVP_PKEY_paramgen(paramsCtx.get(), &tempParams), 0, Operation::LESS_OR_EQUAL);
    m_params.reset(tempParams); 
  }
  
  // ===== Write/Read =====
  void EcParams::WriteParametersToFile(const std::string & filename) const
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_clear_free)> ecGroup(EC_GROUP_new_by_curve_name(m_ellipticCurve), &EC_GROUP_clear_free);
    ThrowSslError<decltype(ecGroup.get())>(ecGroup.get(), nullptr, Operation::EQUAL);

    // 3 step
    ThrowSslError(PEM_write_ECPKParameters(file.get(), ecGroup.get()), 0, Operation::EQUAL);
  }
  
  void EcParams::ReadParametersFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_clear_free)> ecGroup(PEM_read_ECPKParameters(file.get(), nullptr, nullptr, nullptr), &EC_GROUP_clear_free);
    ThrowSslError<decltype(ecGroup.get())>(ecGroup.get(), nullptr, Operation::EQUAL);

    // 3 step
    m_ellipticCurve = EC_GROUP_get_curve_name(ecGroup.get());
    ThrowSslError(m_ellipticCurve, 0, Operation::EQUAL);
    
    // 4 step
    GenerateParameters();
  }
  // ===== Write/Read =====
}
