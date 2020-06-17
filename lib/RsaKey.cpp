#include "RsaKey.h"

#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace openssl_wrapper
{
  const int DEFAULT_KEYGEN_BITS = 2048;
  
  RsaKey::RsaKey():
    Key(),
    m_digestname("SHA1"),
    m_padding(RSA_PKCS1_PADDING),
    m_pssSaltlen(-2),
    m_keygenBits(DEFAULT_KEYGEN_BITS),
    m_pubexp(RSA_F4)
  {}
  
  // ===== Set/Get =====
  void RsaKey::SetDigestName(const std::string & digestname) {
    m_digestname = digestname;
  }

  std::string RsaKey::GetDigestName() const {
    return m_digestname;
  }

  void RsaKey::SetPadding(int padding) {
    m_padding = padding;
  }

  int RsaKey::GetPaddinbg() const {
    return m_padding;
  }

  void RsaKey::SetPssSaltlen(int pssSaltlen) {
    m_pssSaltlen = pssSaltlen;
  }

  int RsaKey::GetPssSaltlen() const {
    return m_pssSaltlen;
  }

  void RsaKey::SetKeygenBits(int keygenBits) {
    m_keygenBits = keygenBits;
  }

  int RsaKey::GetKeygenBits() const {
    return m_keygenBits;
  }
  
  void RsaKey::SetKeygenPubexp(int pubexp) {
    m_pubexp = pubexp;
  }

  int RsaKey::GetKeygenPubexp() const {
    return m_pubexp;
  }

  void RsaKey::SetPlaintext(const bytes_t & plaintext) {
    m_plaintext = plaintext;
  }

  bytes_t RsaKey::GetPlaintext() const {
    return m_plaintext;
  }

  void RsaKey::SetCiphertext(const bytes_t & ciphertext) {
    m_ciphertext = ciphertext;
  }

  bytes_t RsaKey::GetCiphertext() const {
    return m_ciphertext;
  }

  void RsaKey::SetMessage(const bytes_t & message) {
    m_message = message;
  }

  bytes_t RsaKey::GetMessage() const {
    return m_message;
  }

  void RsaKey::SetSignature(const bytes_t & signature) {
    m_signature = signature;
  }

  bytes_t RsaKey::GetSignature() const {
    return m_signature;
  }
  // ===== Set/Get =====
  
  void RsaKey::GenerateKey(const Parameters*)
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
    // 4 step
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
    // 5 step
    EVP_PKEY * tempPkey = nullptr;
    if (EVP_PKEY_keygen(genkeyCtx.get(), &tempPkey) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _pkey.reset(tempPkey);
  }
  
  void RsaKey::Encrypt()
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
    if (EVP_PKEY_CTX_set_rsa_padding(encCtx.get(), _padding) <= 0)
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
    // 5 step
    if (EVP_PKEY_encrypt(encCtx.get(), _ciphertext.data(), &outlen, _plaintext.data(), _plaintext.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _ciphertext.resize(outlen);
  }
  
  void RsaKey::Decrypt()
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
    if (EVP_PKEY_CTX_set_rsa_padding(decCtx.get(), _padding) <= 0)
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
    // 5 step
    if (EVP_PKEY_decrypt(decCtx.get(), _plaintext.data(), &outlen, _ciphertext.data(), _ciphertext.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _plaintext.resize(outlen);
  }
  
  void RsaKey::Sign()
  {
    if (_message.empty())
    {
      throw WrapperException("Message is empty", __FILE__, __LINE__);
    }
    // 1 step
    auto signCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!signCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    const EVP_MD * digestType = EVP_get_digestbyname(_digestname.c_str());
    if (!digestType)
    {
      throw WrapperException("Invalid digest name", __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_sign_init(signCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (EVP_PKEY_CTX_set_rsa_padding(signCtx.get(), _padding) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    if (_padding == RSA_PKCS1_PSS_PADDING)
    {
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen(signCtx.get(), _pssSaltlen) <= 0)
      {
        throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
      }
    }
    // 6 step
    if (EVP_PKEY_CTX_set_signature_md(signCtx.get(), digestType) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 7 step
    std::size_t siglen = 0;
    if (EVP_PKEY_sign(signCtx.get(), nullptr, &siglen, _message.data(), _message.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _signature.resize(siglen);
    // 8 step
    if (EVP_PKEY_sign(signCtx.get(), _signature.data(), &siglen, _message.data(), _message.size()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _signature.resize(siglen);
  }
  
  bool RsaKey::Verify()
  {
    if (_message.empty())
    {
      throw WrapperException("Message is empty", __FILE__, __LINE__);
    }
    if (_signature.empty())
    {
      throw WrapperException("Signature is empty", __FILE__, __LINE__);
    }
    // 1 step
    auto signCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    if (!signCtx)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 2 step
    const EVP_MD * digestType = EVP_get_digestbyname(_digestname.c_str());
    if (!digestType)
    {
      throw WrapperException("Invalid digest name", __FILE__, __LINE__);
    }
    // 3 step
    if (EVP_PKEY_verify_init(signCtx.get()) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 4 step
    if (EVP_PKEY_CTX_set_rsa_padding(signCtx.get(), _padding) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 5 step
    if (_padding == RSA_PKCS1_PSS_PADDING)
    {
      if (EVP_PKEY_CTX_set_rsa_pss_saltlen(signCtx.get(), _pssSaltlen) <= 0)
      {
        throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
      }
    }
    // 6 step
    if (EVP_PKEY_CTX_set_signature_md(signCtx.get(), digestType) <= 0)
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    // 7 step
    switch (EVP_PKEY_verify(signCtx.get(), _signature.data(), _signature.size(), _message.data(), _message.size()))
    {
      case 1:
        return true;
      case 0:
        return false;
      default:
        throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);  
    }
  }
}
