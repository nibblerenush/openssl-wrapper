#include "Cipher.h"

namespace openssl_wrapper
{
  Cipher::Cipher(const std::string & cipherName):
    m_context(nullptr, ContextDeleter),
    m_cipherName(cipherName)
  {}
  
  void Cipher::SetPlaintext(const bytes_t & plaintext) {
    m_plaintext = plaintext;
  }
  
  bytes_t Cipher::GetPlaintext() const {
    return m_plaintext;
  }
  
  void Cipher::SetCiphertext(const bytes_t & ciphertext) {
    m_ciphertext = ciphertext;
  }
  
  bytes_t Cipher::GetCiphertext() const {
    return m_ciphertext;
  }
  
  void Cipher::SetKey(const bytes_t & key) {
    m_key = key;
  }
  
  void Cipher::SetIv(const bytes_t & iv) {
    m_iv = iv;
  }
  
  void Cipher::StartEncrypt()
  {
    // 1 step
    m_context.reset(new EVP_CIPHER_CTX);
    EVP_CIPHER_CTX_init(m_context.get());
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(m_cipherName.c_str());
    if (!evpCipher) {
      throw std::domain_error("Invalid cipher name");
    }

    // 2 step
    ThrowSslError(EVP_EncryptInit_ex(m_context.get(), evpCipher, nullptr, nullptr, nullptr), 0, Operation::EQUAL);

    // 3 step
    if (m_key.size() != EVP_CIPHER_CTX_key_length(m_context.get())) {
      throw std::runtime_error("Invalid key size");
    }

    // 4 step
    if (m_iv.size() != EVP_CIPHER_CTX_iv_length(m_context.get())) {
      throw std::runtime_error("Invalid IV size");
    }

    // 5 step
    ThrowSslError(EVP_EncryptInit_ex(m_context.get(), nullptr, nullptr, m_key.data(), m_iv.data()), 0, Operation::EQUAL);
  }
  
  void Cipher::Encrypt()
  {
    if (m_plaintext.empty()) {
      throw std::domain_error("Plaintext is empty");
    }

    // 1 step
    int outlen = 0;
    m_ciphertext.resize(m_plaintext.size() + EVP_CIPHER_CTX_block_size(m_context.get()) - 1);
    ThrowSslError(EVP_EncryptUpdate(m_context.get(), m_ciphertext.data(), &outlen, m_plaintext.data(), m_plaintext.size()), 0, Operation::EQUAL);
    m_ciphertext.resize(outlen);
  }
  
  void Cipher::FinalEncrypt()
  {
    // 1 step
    bytes_t lastBlock(EVP_CIPHER_CTX_block_size(m_context.get()));
    int tmplen = 0;
    ThrowSslError(EVP_EncryptFinal_ex(m_context.get(), lastBlock.data(), &tmplen), 0, Operation::EQUAL);
    if (tmplen != lastBlock.size()) {
      throw std::runtime_error("Invalid tmplen for last block");
    }
    std::copy(lastBlock.begin(), lastBlock.end(), back_inserter(m_ciphertext));
    m_context.reset(nullptr);
  }
  
  void Cipher::StartDecrypt()
  {
    // 1 step
    m_context.reset(new EVP_CIPHER_CTX);
    EVP_CIPHER_CTX_init(m_context.get());
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(m_cipherName.c_str());
    if (!evpCipher) {
      throw std::domain_error("Invalid cipher name");
    }

    // 2 step
    ThrowSslError(EVP_DecryptInit_ex(m_context.get(), evpCipher, nullptr, nullptr, nullptr), 0, Operation::EQUAL);

    // 3 step
    if (m_key.size() != EVP_CIPHER_CTX_key_length(m_context.get())) {
      throw std::runtime_error("Invalid key size");
    }

    // 4 step
    if (m_iv.size() != EVP_CIPHER_CTX_iv_length(m_context.get())) {
      throw std::runtime_error("Invalid IV size");
    }

    // 5 step
    ThrowSslError(EVP_DecryptInit_ex(m_context.get(), nullptr, nullptr, m_key.data(), m_iv.data()), 0, Operation::EQUAL);
  }
  
  void Cipher::Decrypt()
  {
    if (m_ciphertext.empty()) {
      throw std::domain_error("Ciphertext is empty");
    }

    // 1 step
    int outlen = 0;
    m_plaintext.resize(m_ciphertext.size() + EVP_CIPHER_CTX_block_size(m_context.get()));
    ThrowSslError(EVP_DecryptUpdate(m_context.get(), m_plaintext.data(), &outlen, m_ciphertext.data(), m_ciphertext.size()), 0, Operation::EQUAL);
    m_plaintext.resize(outlen);
  }
  
  void Cipher::FinalDecrypt()
  {
    // 1 step
    bytes_t lastBlock(EVP_CIPHER_CTX_block_size(m_context.get()));
    int tmplen = 0;
    ThrowSslError(EVP_DecryptFinal_ex(m_context.get(), lastBlock.data(), &tmplen), 0, Operation::EQUAL);
    std::copy(lastBlock.begin(), lastBlock.begin() + tmplen, back_inserter(m_plaintext));
    m_context.reset(nullptr);
  }
  
  bytes_t Cipher::Encrypt(const std::string & cipherName, const bytes_t & key, const bytes_t & iv, const bytes_t & plaintext)
  {
    Cipher cipher(cipherName);
    cipher.SetKey(key);
    cipher.SetIv(iv);
    cipher.SetPlaintext(plaintext);
    
    //
    cipher.StartEncrypt();
    cipher.Encrypt();
    cipher.FinalEncrypt();
    return cipher.GetCiphertext();
  }
  
  bytes_t Cipher::Decrypt(const std::string & cipherName, const bytes_t & key, const bytes_t & iv, const bytes_t & ciphertext)
  {
    Cipher cipher(cipherName);
    cipher.SetKey(key);
    cipher.SetIv(iv);
    cipher.SetCiphertext(ciphertext);

    //
    cipher.StartDecrypt();
    cipher.Decrypt();
    cipher.FinalDecrypt();
    return cipher.GetPlaintext();
  }
  
  void Cipher::ContextDeleter(EVP_CIPHER_CTX * context)
  {
    EVP_CIPHER_CTX_cleanup(context);
    delete context;
  }
}
