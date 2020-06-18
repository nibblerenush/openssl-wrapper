# openssl-wrapper
This is the object oriented wrapper library under [OpenSSL](https://www.openssl.org/) libcrypto library.

## Dependencies
* openssl >= 1.0.2

## Build
```cmake <sources folder>```

## Using
It's necessary to call method **Initialize** before using other classes and methods.

```C++
Initialize();

RsaKey rsaKey;
rsaKey.GenerateKey();
rsaKey.SetPlaintext(plaintext);
rsaKey.Encrypt()
std::cout << "plaintext: " << GetAsciiString(plaintext) << '\n'
  << "ciphertext: " << GetHexString(rsaKey.GetCiphertext()) << std::endl;
```
