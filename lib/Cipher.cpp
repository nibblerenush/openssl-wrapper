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
      throw std::domain_error("Invalid key size");
    }

    // 4 step
    if (m_iv.size() != EVP_CIPHER_CTX_iv_length(m_context.get())) {
      throw std::domain_error("Invalid IV size");
    }

    //
    if (!EVP_EncryptInit_ex(_context.get(), nullptr, nullptr, _key.data(), _iv.data()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void Cipher::Encrypt()
  {
    if (_plaintext.empty())
    {
      throw WrapperException("Plaintext is empty", __FILE__, __LINE__);
    }
    //
    int outlen = 0;
    _ciphertext.resize(_plaintext.size() + EVP_CIPHER_CTX_block_size(_context.get()) - 1);
    if(!EVP_EncryptUpdate(_context.get(), _ciphertext.data(), &outlen, _plaintext.data(), _plaintext.size()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _ciphertext.resize(outlen);
  }
  
  void Cipher::FinalEncrypt()
  {
    bytes_t lastBlock(EVP_CIPHER_CTX_block_size(_context.get()));
    int tmplen = 0;
    if(!EVP_EncryptFinal_ex(_context.get(), lastBlock.data(), &tmplen))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    if (tmplen != lastBlock.size())
    {
      throw WrapperException("Invalid tmplen for last block", __FILE__, __LINE__);
    }
    std::copy(lastBlock.begin(), lastBlock.end(), back_inserter(_ciphertext));
    _context.reset(nullptr);
  }
  
  void Cipher::StartDecrypt()
  {
    _context.reset(new EVP_CIPHER_CTX);
    EVP_CIPHER_CTX_init(_context.get());
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(_cipherName.c_str());
    if (!evpCipher)
    {
      throw WrapperException("Invalid cipher name", __FILE__, __LINE__);
    }
    //
    if (!EVP_DecryptInit_ex(_context.get(), evpCipher, nullptr, nullptr, nullptr))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    //
    if (_key.size() != EVP_CIPHER_CTX_key_length(_context.get()))
    {
      throw WrapperException("Invalid key size", __FILE__, __LINE__);
    }
    //
    if (_iv.size() != EVP_CIPHER_CTX_iv_length(_context.get()))
    {
      throw WrapperException("Invalid IV size", __FILE__, __LINE__);
    }
    //
    if (!EVP_DecryptInit_ex(_context.get(), nullptr, nullptr, _key.data(), _iv.data()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
  }
  
  void Cipher::Decrypt()
  {
    if (_ciphertext.empty())
    {
      throw WrapperException("Ciphertext is empty", __FILE__, __LINE__);
    }
    //
    int outlen = 0;
    _plaintext.resize(_ciphertext.size() + EVP_CIPHER_CTX_block_size(_context.get()));
    if (!EVP_DecryptUpdate(_context.get(), _plaintext.data(), &outlen, _ciphertext.data(), _ciphertext.size()))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    _plaintext.resize(outlen);
  }
  
  void Cipher::FinalDecrypt()
  {
    bytes_t lastBlock(EVP_CIPHER_CTX_block_size(_context.get()));
    int tmplen = 0;
    if (!EVP_DecryptFinal_ex(_context.get(), lastBlock.data(), &tmplen))
    {
      throw WrapperException(BaseFunctions::GetSslErrorString(), __FILE__, __LINE__);
    }
    std::copy(lastBlock.begin(), lastBlock.begin() + tmplen, back_inserter(_plaintext));
    _context.reset(nullptr);
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
