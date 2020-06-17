#include "params/DsaParams.h"
#include "BaseFunctions.h"

#include <openssl/dsa.h>
#include <openssl/pem.h>

namespace openssl_wrapper
{
  const int DEFAULT_NBITS = 1024;
  
  DsaParams::DsaParams(): Parameters(), m_nbits(DEFAULT_NBITS)
  {}
  
  // ===== Set/Get =====
  void DsaParams::SetNbits(int nbits) {
    m_nbits = nbits;
  }
  
  int DsaParams::GetNbits() const {
    return m_nbits;
  }
  // ===== Set/Get =====
  
  void DsaParams::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(paramsCtx.get())>(paramsCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_paramgen_init(paramsCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_CTX_set_dsa_paramgen_bits(paramsCtx.get(), m_nbits), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    EVP_PKEY * tempParams = nullptr;
    ThrowSslError(EVP_PKEY_paramgen(paramsCtx.get(), &tempParams), 0, Operation::LESS_OR_EQUAL);
    m_params.reset(tempParams);    
  }
  
  // ===== Write/Read =====
  void DsaParams::WriteParametersToFile(const std::string & filename) const
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    DSA * dsa = EVP_PKEY_get1_DSA(m_params.get());
    ThrowSslError<decltype(dsa)>(dsa, nullptr, Operation::EQUAL);

    // 3 step
    ThrowSslError(PEM_write_DSAparams(file.get(), dsa), 0, Operation::EQUAL);
  }
  
  void DsaParams::ReadParametersFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    DSA * dsa = PEM_read_DSAparams(file.get(), nullptr, nullptr, nullptr);
    ThrowSslError<decltype(dsa)>(dsa, nullptr, Operation::EQUAL);

    // 3 step
    m_params.reset(EVP_PKEY_new());
    ThrowSslError<decltype(m_params.get())>(m_params.get(), nullptr, Operation::EQUAL);

    // 4 step
    ThrowSslError(EVP_PKEY_assign_DSA(m_params.get(), dsa), 0, Operation::EQUAL);
  }
  // ===== Write/Read =====
}
