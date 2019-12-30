cmake_minimum_required(VERSION 3.0)
project(openssl-wrapper)
set(openssl_wrapper_target ${PROJECT_NAME})

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
  lib/Initializer.cpp
  lib/Key.cpp
  lib/KeyAgreement.cpp
  lib/RsaKey.cpp)

set(headers
  include/openssl-wrapper/params/DhParams.h
  include/openssl-wrapper/params/DsaParams.h
  include/openssl-wrapper/params/EcParams.h
  include/openssl-wrapper/params/Parameters.h
  include/openssl-wrapper/BaseFunctions.h
  include/openssl-wrapper/Cipher.h
  include/openssl-wrapper/Digest.h
  include/openssl-wrapper/DigitalSignature.h
  include/openssl-wrapper/Hmac.h
  include/openssl-wrapper/Initializer.h
  include/openssl-wrapper/Key.h
  include/openssl-wrapper/KeyAgreement.h
  include/openssl-wrapper/RsaKey.h)

add_library(${openssl_wrapper_target} STATIC ${sources} ${headers})
target_include_directories(${openssl_wrapper_target} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include/openssl-wrapper)
target_link_libraries(${openssl_wrapper_target} PUBLIC OpenSSL::Crypto OpenSSL::SSL)

install(TARGETS ${openssl_wrapper_target} DESTINATION /usr/lib64)
install(DIRECTORY include/openssl-wrapper DESTINATION /usr/include)

option(BUILD_EXAMPLES "For building examples" ON)
if(BUILD_EXAMPLES)
  add_subdirectory(examples)
endif(BUILD_EXAMPLES)
