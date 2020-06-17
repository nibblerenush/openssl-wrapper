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
    ThrowSslError<decltype(genkeyCtx.get())>(genkeyCtx.get(), nullptr, Operation::EQUAL);
    
    // 2 step
    ThrowSslError(EVP_PKEY_keygen_init(genkeyCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_CTX_set_rsa_keygen_bits(genkeyCtx.get(), m_keygenBits), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    BIGNUM * pubexp = BN_new();
    ThrowSslError<decltype(pubexp)>(pubexp, nullptr, Operation::EQUAL);
    ThrowSslError(BN_set_word(pubexp, m_pubexp), 0, Operation::EQUAL);
    ThrowSslError(EVP_PKEY_CTX_set_rsa_keygen_pubexp(genkeyCtx.get(), pubexp), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    EVP_PKEY * tempPkey = nullptr;
    ThrowSslError(EVP_PKEY_keygen(genkeyCtx.get(), &tempPkey), 0, Operation::LESS_OR_EQUAL);
    m_pkey.reset(tempPkey);
  }

  void RsaKey::Encrypt()
  {
    if (m_plaintext.empty()) {
      throw std::domain_error("Plaintext is empty");
    }

    // 1 step
    auto encCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(m_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(encCtx.get())>(encCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_encrypt_init(encCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_CTX_set_rsa_padding(encCtx.get(), m_padding), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    std::size_t outlen = 0;
    ThrowSslError(EVP_PKEY_encrypt(encCtx.get(), nullptr, &outlen, m_plaintext.data(), m_plaintext.size()), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    m_ciphertext.resize(outlen);
    ThrowSslError(EVP_PKEY_encrypt(encCtx.get(), m_ciphertext.data(), &outlen, m_plaintext.data(), m_plaintext.size()), 0, Operation::LESS_OR_EQUAL);
    m_ciphertext.resize(outlen);
  }
  
  void RsaKey::Decrypt()
  {
    if (m_ciphertext.empty()) {
      throw std::domain_error("Ciphertext is empty");
    }

    // 1 step
    auto decCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(m_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(decCtx.get())>(decCtx.get(), nullptr, Operation::EQUAL);

    // 2 step
    ThrowSslError(EVP_PKEY_decrypt_init(decCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_CTX_set_rsa_padding(decCtx.get(), m_padding), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    std::size_t outlen = 0;
    ThrowSslError(EVP_PKEY_decrypt(decCtx.get(), nullptr, &outlen, m_ciphertext.data(), m_ciphertext.size()), 0, Operation::LESS_OR_EQUAL);
    
    // 5 step
    m_plaintext.resize(outlen);
    ThrowSslError(EVP_PKEY_decrypt(decCtx.get(), m_plaintext.data(), &outlen, m_ciphertext.data(), m_ciphertext.size()), 0, Operation::LESS_OR_EQUAL);
    m_plaintext.resize(outlen);
  }
  
  void RsaKey::Sign()
  {
    if (m_message.empty()) {
      throw std::domain_error("Message is empty");
    }

    // 1 step
    const EVP_MD * digestType = EVP_get_digestbyname(m_digestname.c_str());
    if (!digestType) {
      throw std::domain_error("Invalid digest name");
    }

    // 2 step
    auto signCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(m_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(signCtx.get())>(signCtx.get(), nullptr, Operation::EQUAL);

    // 3 step
    ThrowSslError(EVP_PKEY_sign_init(signCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    ThrowSslError(EVP_PKEY_CTX_set_rsa_padding(signCtx.get(), m_padding), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    if (m_padding == RSA_PKCS1_PSS_PADDING) {
      ThrowSslError(EVP_PKEY_CTX_set_rsa_pss_saltlen(signCtx.get(), m_pssSaltlen), 0, Operation::LESS_OR_EQUAL);
    }

    // 6 step
    ThrowSslError(EVP_PKEY_CTX_set_signature_md(signCtx.get(), digestType), 0, Operation::LESS_OR_EQUAL);

    // 7 step
    std::size_t siglen = 0;
    ThrowSslError(EVP_PKEY_sign(signCtx.get(), nullptr, &siglen, m_message.data(), m_message.size()), 0, Operation::LESS_OR_EQUAL);

    // 8 step
    m_signature.resize(siglen);
    ThrowSslError(EVP_PKEY_sign(signCtx.get(), m_signature.data(), &siglen, m_message.data(), m_message.size()), 0, Operation::LESS_OR_EQUAL);
    m_signature.resize(siglen);
  }
  
  bool RsaKey::Verify()
  {
    if (m_message.empty()) {
      throw std::domain_error("Message is empty");
    }

    if (m_signature.empty()) {
      throw std::domain_error("Signature is empty");
    }

    // 1 step
    const EVP_MD * digestType = EVP_get_digestbyname(m_digestname.c_str());
    if (!digestType) {
      throw std::domain_error("Invalid digest name");
    }

    // 2 step
    auto verifyCtx = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>(EVP_PKEY_CTX_new(m_pkey.get(), nullptr), &EVP_PKEY_CTX_free);
    ThrowSslError<decltype(verifyCtx.get())>(verifyCtx.get(), nullptr, Operation::EQUAL);
    
    // 3 step
    ThrowSslError(EVP_PKEY_verify_init(verifyCtx.get()), 0, Operation::LESS_OR_EQUAL);

    // 4 step
    ThrowSslError(EVP_PKEY_CTX_set_rsa_padding(verifyCtx.get(), m_padding), 0, Operation::LESS_OR_EQUAL);

    // 5 step
    if (m_padding == RSA_PKCS1_PSS_PADDING) {
      ThrowSslError(EVP_PKEY_CTX_set_rsa_pss_saltlen(verifyCtx.get(), m_pssSaltlen), 0, Operation::LESS_OR_EQUAL);
    }

    // 6 step
    ThrowSslError(EVP_PKEY_CTX_set_signature_md(verifyCtx.get(), digestType), 0, Operation::LESS_OR_EQUAL);

    // 7 step
    switch (EVP_PKEY_verify(verifyCtx.get(), m_signature.data(), m_signature.size(), m_message.data(), m_message.size()))
    {
      case 1:
        return true;
      case 0:
        return false;
      default:
        ThrowSslError(0, 0, Operation::EQUAL);
    }
  }
}
