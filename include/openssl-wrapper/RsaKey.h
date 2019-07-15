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
    std::string _digestname;
    int _padding;
    int _pssSaltlen;
    int _keygenBits;
    int _pubexp;
    bytes_t _plaintext;
    bytes_t _ciphertext;
    bytes_t _message;
    bytes_t _signature;
  private:
    static const int DEFAULT_KEYGEN_BITS;
  };
}
