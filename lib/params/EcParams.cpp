#include "EcParams.h"
#include "BaseFunctions.h"

#include <openssl/ec.h>
#include <openssl/pem.h>

namespace openssl_wrapper
{
  EcParams::EcParams():
  Parameters(),
  _ellipticCurve(NID_X9_62_prime256v1)
  {}
  
  // ===== Set/Get =====
  void EcParams::SetEllipticCurve(int ellipticCurve)
  {
    _ellipticCurve = ellipticCurve;
  }
  int EcParams::GetEllipticCurve() const
  {
    return _ellipticCurve;
  }
  // ===== Set/Get =====
  
  void EcParams::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), &EVP_PKEY_CTX_free);
    if (!paramsCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_paramgen_init(paramsCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramsCtx.get(), _ellipticCurve) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    EVP_PKEY * tempParams = nullptr;
    if (EVP_PKEY_paramgen(paramsCtx.get(), &tempParams) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _params.reset(tempParams);
  }
  
  // ===== Write/Read =====
  void EcParams::WriteParametersToFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_clear_free)> ecGroup(EC_GROUP_new_by_curve_name(_ellipticCurve), &EC_GROUP_clear_free);
    if (!ecGroup)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (!PEM_write_ECPKParameters(file.get(), ecGroup.get()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void EcParams::ReadParametersFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_clear_free)> ecGroup(PEM_read_ECPKParameters(file.get(), nullptr, nullptr, nullptr), &EC_GROUP_clear_free);
    if (!ecGroup)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    int _ellipticCurve = EC_GROUP_get_curve_name(ecGroup.get()); // BUG from OpenSSL
    if (!_ellipticCurve)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    GenerateParameters();
  }
  // ===== Write/Read =====
}
