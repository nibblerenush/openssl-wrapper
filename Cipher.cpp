#include "Cipher.h"
#include "BaseFunctions.h"

#include <iostream>

namespace openssl_wrapper
{  
  CipherException::CipherException(const std::string & info):
  std::exception(),
  _info(info)
  {}
  
  const char * CipherException::what() const noexcept
  {
    return _info.c_str();
  }
  
  Cipher::Cipher(const std::string & cipherName):
  _context(new EVP_CIPHER_CTX, EVP_CIPHER_CTX_cleanup)
  {
    EVP_CIPHER_CTX_init(_context.get());
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(cipherName.c_str());
    if (!evpCipher)
    {
      throw CipherException("Invalid cipher name");
    }
    //
    
    if (!EVP_EncryptInit_ex(_context.get(), evpCipher, nullptr, nullptr, nullptr))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
  }
  
  void Cipher::SetPlaintext(const std::vector<uint8_t> & plaintext)
  {
    _plaintext = plaintext;
  }
  
  std::vector<uint8_t> Cipher::GetPlaintext() const
  {
    return _plaintext;
  }
  
  void Cipher::SetCiphertext(const std::vector<uint8_t> & ciphertext)
  {
    _ciphertext = ciphertext;
  }
  
  std::vector<uint8_t> Cipher::GetCiphertext() const
  {
    return _ciphertext;
  }
  
  void Cipher::SetKey(const std::vector<uint8_t> & key)
  {
    if (key.size() != EVP_CIPHER_CTX_key_length(_context.get()))
    {
      throw CipherException("Invalid key size");
    }
    _key = key;
  }
  
  void Cipher::SetIv(const std::vector<uint8_t> & iv)
  {
    if (iv.size() != EVP_CIPHER_CTX_iv_length(_context.get()))
    {
      throw CipherException("Invalid IV size");
    }
    _iv = iv;
  }
  
  void Cipher::Encrypt()
  {
    if (_plaintext.empty())
    {
      throw CipherException("Plaintext is empty");
    }
    // 1 step
    if (!EVP_EncryptInit_ex(_context.get(), nullptr, nullptr, _key.data(), _iv.data()))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    
    // 2 step
    int outlen = 0;
    _ciphertext.resize(_plaintext.size() + EVP_CIPHER_CTX_block_size(_context.get()) - 1);
    if(!EVP_EncryptUpdate(_context.get(), _ciphertext.data(), &outlen, _plaintext.data(), _plaintext.size()))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    _ciphertext.resize(outlen);
    
    // 3 step
    std::vector<uint8_t> lastBlock(EVP_CIPHER_CTX_block_size(_context.get()));
    int tmplen = 0;
    if(!EVP_EncryptFinal_ex(_context.get(), lastBlock.data(), &tmplen))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    if (tmplen != lastBlock.size())
    {
      throw CipherException("Invalid tmplen for last block");
    }
    std::copy(lastBlock.begin(), lastBlock.end(), back_inserter(_ciphertext));
  }
}
