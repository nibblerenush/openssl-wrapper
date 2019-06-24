#include "RsaCrypto.h"

#include <openssl/pem.h>

namespace openssl_wrapper
{
  const int RsaCrypto::DEFAULT_KEYGEN_BITS = 2048;
  
  RsaCrypto::RsaCrypto():
  _pkey(nullptr, &EVP_PKEY_free),
  _keygenBits(DEFAULT_KEYGEN_BITS),
  _pubexp(RSA_F4),
  _padding(Padding::RSA_PKCS1)
  {}
  
  void RsaCrypto::SetKeygenBits(int keygenBits)
  {
    _keygenBits = keygenBits;
  }
  
  void RsaCrypto::SetKeygenPubexp(int pubexp)
  {
    _pubexp = pubexp;
  }
  
  void RsaCrypto::SetPadding(Padding padding)
  {
    _padding = padding;
  }
  
  void RsaCrypto::GenerateKey()
  {
    // 1 step
    auto genkeyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), &EVP_PKEY_CTX_free);
    if (!genkeyCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_keygen_init(genkeyCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(genkeyCtx.get(), _keygenBits) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    //
    BIGNUM * pubexp = BN_new();
    if (!pubexp)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    if (!BN_set_word(pubexp, _pubexp))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(genkeyCtx.get(), pubexp) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    EVP_PKEY * tempPkey = nullptr;
    if (EVP_PKEY_keygen(genkeyCtx.get(), &tempPkey) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  void RsaCrypto::WritePrivateKeyToFile(const std::string & filename, const std::string & cipherName, const std::string & pass)
  {
    if (pass.size() < 4)
    {
      throw WrapperException("Invalid pass size (must be >= 4)", __FILE__, __LINE__);
    }
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(cipherName.c_str());
    if (!evpCipher)
    {
      throw WrapperException("Invalid cipher name", __FILE__, __LINE__);
    }
    //
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    RSA * rsa = EVP_PKEY_get1_RSA(_pkey.get());
    if (!PEM_write_RSAPrivateKey(file.get(), rsa, evpCipher, (unsigned char*)pass.c_str(), pass.length(), nullptr, nullptr))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void RsaCrypto::ReadPrivateKeyFromFile(const std::string & filename, const std::string & pass)
  {
    if (pass.size() < 4)
    {
      throw WrapperException("Invalid pass size (must be >= 4)", __FILE__, __LINE__);
    }
    //
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    EVP_PKEY * tempPkey = PEM_read_PrivateKey(file.get(), nullptr, nullptr, (void*)pass.c_str());
    if (!tempPkey)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  void RsaCrypto::WritePublicKeyToFile(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "wb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    RSA * rsa = EVP_PKEY_get1_RSA(_pkey.get());
    if (!PEM_write_RSAPublicKey(file.get(), rsa))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void RsaCrypto::ReadPublicKeyFromFile(const std::string & filename)
  {
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(filename.c_str(), "rb"), &std::fclose);
    if (!file)
    {
      throw WrapperException(BaseFunctions::GetOsErrorString(), __FILE__, __LINE__);
    }
    //
    EVP_PKEY * tempPkey = PEM_read_PUBKEY(file.get(), nullptr, nullptr, nullptr);
    if (!tempPkey)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  void RsaCrypto::SetPlaintext(const bytes_t & plaintext)
  {
    _plaintext = plaintext;
  }
  
  bytes_t RsaCrypto::GetPlaintext() const
  {
    return _plaintext;
  }
  
  void RsaCrypto::SetCiphertext(const bytes_t & ciphertext)
  {
    _ciphertext = ciphertext;
  }
  
  bytes_t RsaCrypto::GetCiphertext() const
  {
    return _ciphertext;
  }
  
  void RsaCrypto::Encrypt()
  {
    if (_plaintext.empty())
    {
      throw WrapperException("Plaintext is empty", __FILE__, __LINE__);
    }
    // 1 step
    auto encCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!encCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }    
    // 2 step
    if (EVP_PKEY_encrypt_init(encCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_CTX_set_rsa_padding(encCtx.get(), static_cast<int>(_padding)) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    std::size_t outlen = 0;
    if (EVP_PKEY_encrypt(encCtx.get(), nullptr, &outlen, _plaintext.data(), _plaintext.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _ciphertext.resize(outlen);
    //
    if (EVP_PKEY_encrypt(encCtx.get(), _ciphertext.data(), &outlen, _plaintext.data(), _plaintext.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _ciphertext.resize(outlen);
  }
  
  void RsaCrypto::Decrypt()
  {
    if (_ciphertext.empty())
    {
      throw WrapperException("Ciphertext is empty", __FILE__, __LINE__);
    }
    // 1 step
    auto decCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!decCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    if (EVP_PKEY_decrypt_init(decCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_CTX_set_rsa_padding(decCtx.get(), static_cast<int>(_padding)) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    std::size_t outlen = 0;
    if (EVP_PKEY_decrypt(decCtx.get(), nullptr, &outlen, _ciphertext.data(), _ciphertext.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _plaintext.resize(outlen);
    //
    if (EVP_PKEY_decrypt(decCtx.get(), _plaintext.data(), &outlen, _ciphertext.data(), _ciphertext.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _plaintext.resize(outlen);
  }
}
