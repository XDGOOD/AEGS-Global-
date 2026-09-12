cmake_minimum_required(VERSION 3.16)
project(AegsGlobal CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -std=c++17")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

# ASan / UBSan sanitizer build option per Stage 21
option(ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ENABLE_ASAN)
    message(STATUS "Enabling AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan)")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

# TSAN build option per Stage 22
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
if(ENABLE_TSAN)
    message(STATUS "Enabling ThreadSanitizer (TSAN)")
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=thread)
endif()

set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# Shared sources
set(CORE_SOURCES
    port_hopper.cpp
    protocol_mimicry.cpp
    traffic_shaper.cpp
    chaff_engine.cpp
    illusion_prebypass.cpp
    blackhole_responder.cpp
    network_security.cpp
)

# 1. Main Carrier-Grade Server
add_executable(aegs_server server.cpp tun_interface.cpp ip_router.cpp handshake.cpp ip_pool.cpp nat_manager.cpp ${CORE_SOURCES})
target_include_directories(aegs_server PRIVATE ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(aegs_server PRIVATE OpenSSL::Crypto ${SQLITE3_LIBRARIES} Threads::Threads)

# 2. Client
add_executable(aegs_client client.cpp tun_interface.cpp ip_router.cpp handshake.cpp ip_pool.cpp nat_manager.cpp ${CORE_SOURCES})
target_link_libraries(aegs_client PRIVATE OpenSSL::Crypto Threads::Threads)

# 3. Test Runner
add_executable(aegs_test test_runner.cpp tun_interface.cpp ip_router.cpp handshake.cpp ip_pool.cpp nat_manager.cpp ${CORE_SOURCES})
target_link_libraries(aegs_test PRIVATE OpenSSL::Crypto Threads::Threads)

# 4. Stage 26 Benchmark Suite
add_executable(bench_hotpath benchmarks/bench_hotpath.cpp ${CORE_SOURCES})
target_link_libraries(bench_hotpath PRIVATE OpenSSL::Crypto Threads::Threads)
# 5. Stage 23 Protocol Fuzz Target
add_executable(aegs_fuzz fuzzing/fuzz_parsers.cpp ${CORE_SOURCES})
target_link_libraries(aegs_fuzz PRIVATE OpenSSL::Crypto Threads::Threads)
