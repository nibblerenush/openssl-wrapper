set(target examples)
set(sources main.cpp)

add_executable(${target} ${sources})
target_link_libraries(${target} ${openssl_wrapper_target})
