#include "Key.h"
#include "BaseFunctions.h"

#include <openssl/pem.h>

namespace openssl_wrapper
{
  Key::Key(): m_pkey(nullptr, &EVP_PKEY_free)
  {}
  
  void Key::GenerateKey(const Parameters * params)
  {
    if (!params) {
      throw std::invalid_argument("Null parameters");
    }

    // 1 step
    auto keygenCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(params->m_params.get(), nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(keygenCtx.get())>(keygenCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_keygen_init(keygenCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    EVP_PKEY * tempPkey = nullptr;
    ThrowSslError(EVP_PKEY_keygen(keygenCtx.get(), &tempPkey), 0, Operation::LESS_OR_EQUAL);
    m_pkey.reset(tempPkey);
  }
  
  // ===== Write/Read =====
  void Key::WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass) const
  {
    if (pass.size() < 4) {
      throw std::invalid_argument("Invalid pass size (must be >= 4)");
    }

    // 1 step
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(cipherName.c_str());
    if (!evpCipher) {
      throw std::invalid_argument("Invalid cipher name");
    }

    // 2 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 3 step
    ThrowSslError(PEM_write_PrivateKey(file.get(), m_pkey.get(), evpCipher, (unsigned char*)pass.c_str(), pass.length(), nullptr, nullptr), 0, Operation::EQUAL);
  }
  
  void Key::ReadPrivateKeyFromFile(const std::string & filename, const std::string & pass)
  {
    if (pass.size() < 4) {
      throw std::invalid_argument("Invalid pass size (must be >= 4)");
    }

    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    EVP_PKEY * tempPkey = PEM_read_PrivateKey(file.get(), nullptr, nullptr, (void*)pass.c_str());
    ThrowSslError<decltype(tempPkey)>(tempPkey, nullptr, Operation::EQUAL);
    m_pkey.reset(tempPkey);
  }
  
  void Key::WritePublicKeyToFile(const std::string & filename) const
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(PEM_write_PUBKEY(file.get(), m_pkey.get()), 0, Operation::EQUAL);
  }
  
  void Key::ReadPublicKeyFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    ThrowSystemError<decltype(file.get())>(file.get(), nullptr, Operation::EQUAL);

    // 2 step
    EVP_PKEY * tempPkey = PEM_read_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    ThrowSslError<decltype(tempPkey)>(tempPkey, nullptr, Operation::EQUAL);
    m_pkey.reset(tempPkey);
  }
  // ===== Write/Read =====
}
