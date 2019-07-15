#include "Key.h"
#include "BaseFunctions.h"

#include <openssl/pem.h>

namespace openssl_wrapper
{
  Key::Key():
  _pkey(nullptr, &EVP_PKEY_free)
  {}
  
  void Key::GenerateKey(const Parameters * params)
  {
    if (!params)
    {
      throw WrapperException("Null parameters", __FILE__, __LINE__);
    }
    // 1 step
    auto keygenCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(params->_params.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!keygenCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_keygen_init(keygenCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    EVP_PKEY * tempPkey = nullptr;
    if (EVP_PKEY_keygen(keygenCtx.get(), &tempPkey) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  // ===== Write/Read =====
  void Key::WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass)
  {
    if (pass.size() < 4)
    {
      throw WrapperException("Invalid pass size (must be >= 4)", __FILE__, __LINE__);
    }
    // 1 step
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(cipherName.c_str());
    if (!evpCipher)
    {
      throw WrapperException("Invalid cipher name", __FILE__, __LINE__);
    }
    // 2 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (!PEM_write_PrivateKey(file.get(), _pkey.get(), evpCipher, (unsigned char*)pass.c_str(), pass.length(), nullptr, nullptr))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void Key::ReadPrivateKeyFromFile(const std::string & filename, const std::string & pass)
  {
    if (pass.size() < 4)
    {
      throw WrapperException("Invalid pass size (must be >= 4)", __FILE__, __LINE__);
    }
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    EVP_PKEY * tempPkey = PEM_read_PrivateKey(file.get(), nullptr, nullptr, (void*)pass.c_str());
    if (!tempPkey)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  void Key::WritePublicKeyToFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (!PEM_write_PUBKEY(file.get(), _pkey.get()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void Key::ReadPublicKeyFromFile(const std::string & filename)
  {
    // 1 step
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    EVP_PKEY * tempPkey = PEM_read_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    if (!tempPkey)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  // ===== Write/Read =====
}
