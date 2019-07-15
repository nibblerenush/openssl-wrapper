cmake_minimum_required(VERSION 3.0)
project(openssl-wrapper)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  message("OPENSSL_VERSION: " ${OPENSSL_VERSION})
  message("OPENSSL_LIBRARIES: " ${OPENSSL_LIBRARIES})
endif(OPENSSL_FOUND)

set(sources
  lib/params/DhParams.cpp
  lib/params/DsaParams.cpp
  lib/params/EcParams.cpp
  lib/params/Parameters.cpp
  lib/BaseFunctions.cpp
  lib/Cipher.cpp
  lib/Digest.cpp
  lib/DigitalSignature.cpp
  lib/Hmac.cpp
  lib/Key.cpp
  lib/KeyAgreement.cpp
  lib/RsaKey.cpp)

set(headers
  include/params/DhParams.h
  include/params/DsaParams.h
  include/params/EcParams.h
  include/params/Parameters.h
  include/BaseFunctions.h
  include/Cipher.h
  include/Digest.h
  include/DigitalSignature.h
  include/Hmac.h
  include/Key.h
  include/KeyAgreement.h
  include/RsaKey.h)

add_library(${PROJECT_NAME} STATIC ${sources} ${headers})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME} PUBLIC OpenSSL::Crypto OpenSSL::SSL)

option(BUILD_EXAMPLES "For building examples" ON)
if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif(BUILD_EXAMPLES)
