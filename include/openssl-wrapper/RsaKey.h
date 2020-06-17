#pragma once

#include "Key.h"
#include "BaseFunctions.h"

namespace openssl_wrapper
{
  class RsaKey: public Key
  {
  public:
    RsaKey();
    // ===== Set/Get =====
    void SetDigestName(const std::string & digestname);
    std::string GetDigestName() const;
    void SetPadding(int padding);
    int GetPaddinbg() const;
    void SetPssSaltlen(int pssSaltlen);
    int GetPssSaltlen() const;
    void SetKeygenBits(int keygenBits);
    int GetKeygenBits() const;
    void SetKeygenPubexp(int pubexp);
    int GetKeygenPubexp() const;
    void SetPlaintext(const bytes_t & plaintext);
    bytes_t GetPlaintext() const;
    void SetCiphertext(const bytes_t & ciphertext);
    bytes_t GetCiphertext() const;
    void SetMessage(const bytes_t & message);
    bytes_t GetMessage() const;
    void SetSignature(const bytes_t & signature);
    bytes_t GetSignature() const;
    // ===== Set/Get =====
    void GenerateKey(const Parameters * params = nullptr) override;
    void Encrypt();
    void Decrypt();
    void Sign();
    bool Verify();
  private:
    std::string m_digestname;
    int m_padding;
    int m_pssSaltlen;
    int m_keygenBits;
    int m_pubexp;
    bytes_t m_plaintext;
    bytes_t m_ciphertext;
    bytes_t m_message;
    bytes_t m_signature;
  };
}
