cmake_minimum_required(VERSION 3.0)
project(openssl-wrapper)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  message("OPENSSL_VERSION: " ${OPENSSL_VERSION})
  message("OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES})
endif()

set(sources
  BaseFunctions.cpp
  Cipher.cpp
  DhCrypto.cpp
  DhParams.cpp
  DsaParams.cpp
  EcdhCrypto.cpp
  EcParams.cpp
  Key.cpp
  KeyAgreement.cpp
  Parameters.cpp
  RsaCrypto.cpp
  main.cpp)

set(headers
  BaseFunctions.h
  Cipher.h
  DhCrypto.h
  DhParams.h
  DsaParams.h
  EcdhCrypto.h
  EcParams.h
  Key.h
  KeyAgreement.h
  Parameters.h
  RsaCrypto.h)

add_executable(${PROJECT_NAME} ${sources} ${headers})
target_link_libraries(${PROJECT_NAME} OpenSSL::Crypto OpenSSL::SSL)
