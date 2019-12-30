#include "Initializer.h"
#include <openssl/evp.h>
#include <openssl/err.h>

namespace openssl_wrapper
{
  class Initializer
  {
  public:
    static void Instance();
    ~Initializer();
  private:
    explicit Initializer();
    Initializer(const Initializer &) = delete;
    Initializer(const Initializer &&) = delete;
    Initializer & operator=(const Initializer &) = delete;
    Initializer & operator=(const Initializer &&) = delete;
  };

  Initializer::Initializer()
  {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
  }

  Initializer::~Initializer()
  {
    ERR_free_strings();
    EVP_cleanup();
  }

  void Initializer::Instance()
  {
    static Initializer initializer;
  }

  void Initialize()
  {
    Initializer::Instance();
  }
}
