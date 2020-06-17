#include "params/DhParams.h"
#include "BaseFunctions.h"

#include <openssl/dh.h>
#include <openssl/pem.h>

namespace openssl_wrapper
{
  const int DEFAULT_PRIME_LEN = 1024;
  
  DhParams::DhParams(): Parameters(), m_primeLen(DEFAULT_PRIME_LEN), m_generator(DH_GENERATOR_2)
  {}
  
  // ===== Set/Get =====
  void DhParams::SetPrimeLen(int primeLen) {
    m_primeLen = primeLen;
  }

  int DhParams::GetPrimeLen() const {
    return m_primeLen;
  }

  void DhParams::SetGenerator(int generator) {
    m_generator = generator;
  }

  int DhParams::GetGenerator() const {
    return m_generator;
  }
  // ===== Set/Get =====
  
  void DhParams::GenerateParameters()
  {
    // 1 step
    auto paramsCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_DH, nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(paramsCtx.get())>(paramsCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_paramgen_init(paramsCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_CTX_set_dh_paramgen_prime_len(paramsCtx.get(), m_primeLen), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    ThrowSslError(EVP_PKEY_CTX_set_dh_paramgen_generator(paramsCtx.get(), m_generator), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    EVP_PKEY* tempParams = nullptr;
    ThrowSslError(EVP_PKEY_paramgen(paramsCtx.get(), &tempParams), 0, Operation::LESS_OR_EQUAL);
    m_params.reset(tempParams);
  }
  
  // ===== Write/Read =====
  void DhParams::WriteParametersToFile(const std::string & filename) const
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    DH* dh = EVP_PKEY_get1_DH(m_params.get());
    ThrowSslError<decltype(dh)>(dh, nullptr, Operation::EQUAL);

    // 3 step
    ThrowSslError(PEM_write_DHparams(file.get(), dh), 0, Operation::EQUAL);
  }
  
  void DhParams::ReadParametersFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    DH* dh = PEM_read_DHparams(file.get(), nullptr, nullptr, nullptr);
    ThrowSslError<decltype(dh)>(dh, nullptr, Operation::EQUAL);

    // 3 step
    m_params.reset(EVP_PKEY_new());
    ThrowSslError<decltype(m_params.get())>(m_params.get(), nullptr, Operation::EQUAL);

    // 4 step
    ThrowSslError(EVP_PKEY_assign_DH(m_params.get(), dh), 0, Operation::EQUAL);
  }
  // ===== Write/Read =====
}
