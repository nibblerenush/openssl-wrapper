#include "Cipher.h"
#include "BaseFunctions.h"

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
  _context(nullptr, ContextDeleter),
  _cipherName(cipherName)
  {}
  
  void Cipher::SetPlaintext(const bytes & plaintext)
  {
    _plaintext = plaintext;
  }
  
  bytes Cipher::GetPlaintext() const
  {
    return _plaintext;
  }
  
  void Cipher::SetCiphertext(const bytes & ciphertext)
  {
    _ciphertext = ciphertext;
  }
  
  bytes Cipher::GetCiphertext() const
  {
    return _ciphertext;
  }
  
  void Cipher::SetKey(const std::vector<uint8_t> & key)
  {
    _key = key;
  }
  
  void Cipher::SetIv(const std::vector<uint8_t> & iv)
  {
    _iv = iv;
  }
  
  void Cipher::StartEncrypt()
  {
    _context.reset(new EVP_CIPHER_CTX);
    EVP_CIPHER_CTX_init(_context.get());
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(_cipherName.c_str());
    if (!evpCipher)
    {
      throw CipherException("Invalid cipher name");
    }
    //
    if (!EVP_EncryptInit_ex(_context.get(), evpCipher, nullptr, nullptr, nullptr))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    //
    if (_key.size() != EVP_CIPHER_CTX_key_length(_context.get()))
    {
      throw CipherException("Invalid key size");
    }
    //
    if (_iv.size() != EVP_CIPHER_CTX_iv_length(_context.get()))
    {
      throw CipherException("Invalid IV size");
    }
    //
    if (!EVP_EncryptInit_ex(_context.get(), nullptr, nullptr, _key.data(), _iv.data()))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
  }
  
  void Cipher::Encrypt()
  {
    if (_plaintext.empty())
    {
      throw CipherException("Plaintext is empty");
    }
    //
    int outlen = 0;
    _ciphertext.resize(_plaintext.size() + EVP_CIPHER_CTX_block_size(_context.get()) - 1);
    if(!EVP_EncryptUpdate(_context.get(), _ciphertext.data(), &outlen, _plaintext.data(), _plaintext.size()))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    _ciphertext.resize(outlen);
  }
  
  void Cipher::FinalEncrypt()
  {
    bytes lastBlock(EVP_CIPHER_CTX_block_size(_context.get()));
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
    _context.reset(nullptr);
  }
  
  void Cipher::StartDecrypt()
  {
    _context.reset(new EVP_CIPHER_CTX);
    EVP_CIPHER_CTX_init(_context.get());
    const EVP_CIPHER * evpCipher = EVP_get_cipherbyname(_cipherName.c_str());
    if (!evpCipher)
    {
      throw CipherException("Invalid cipher name");
    }
    //
    if (!EVP_DecryptInit_ex(_context.get(), evpCipher, nullptr, nullptr, nullptr))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    //
    if (_key.size() != EVP_CIPHER_CTX_key_length(_context.get()))
    {
      throw CipherException("Invalid key size");
    }
    //
    if (_iv.size() != EVP_CIPHER_CTX_iv_length(_context.get()))
    {
      throw CipherException("Invalid IV size");
    }
    //
    if (!EVP_DecryptInit_ex(_context.get(), nullptr, nullptr, _key.data(), _iv.data()))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
  }
  
  void Cipher::Decrypt()
  {
    if (_ciphertext.empty())
    {
      throw CipherException("Ciphertext is empty");
    }
    //
    int outlen = 0;
    _plaintext.resize(_ciphertext.size() + EVP_CIPHER_CTX_block_size(_context.get()));
    if (!EVP_DecryptUpdate(_context.get(), _plaintext.data(), &outlen, _ciphertext.data(), _ciphertext.size()))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    _plaintext.resize(outlen);
  }
  
  void Cipher::FinalDecrypt()
  {
    bytes lastBlock(EVP_CIPHER_CTX_block_size(_context.get()));
    int tmplen = 0;
    if (!EVP_DecryptFinal_ex(_context.get(), lastBlock.data(), &tmplen))
    {
      throw CipherException(BaseFunctions::GetSslErrorString());
    }
    std::copy(lastBlock.begin(), lastBlock.begin() + tmplen, back_inserter(_plaintext));
    _context.reset(nullptr);
  }
  
  bytes Cipher::Encrypt(const std::string & cipherName, const bytes & key, const bytes & iv, const bytes & plaintext)
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
  
  bytes Cipher::Decrypt(const std::string & cipherName, const bytes & key, const bytes & iv, const bytes & ciphertext)
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
