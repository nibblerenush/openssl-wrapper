cmake_minimum_required(VERSION 3.0)
project(openssl-wrapper)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  message("OPENSSL_VERSION: " ${OPENSSL_VERSION})
  message("OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES})
endif()

set(sources
  params/DhParams.cpp
  params/DsaParams.cpp
  params/EcParams.cpp
  params/Parameters.cpp
  BaseFunctions.cpp
  Cipher.cpp
  DigitalSignature.cpp
  Key.cpp
  KeyAgreement.cpp
  RsaCrypto.cpp
  main.cpp)

set(headers
  params/DhParams.h
  params/DsaParams.h
  params/EcParams.h
  params/Parameters.h
  BaseFunctions.h
  Cipher.h
  DigitalSignature.h
  Key.h
  KeyAgreement.h
  RsaCrypto.h)

add_executable(${PROJECT_NAME} ${sources} ${headers})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto OpenSSL::SSL)
