cmake_minimum_required(VERSION 3.16)
project(AegisVPN CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# FIX: добавлены базовые флаги хардненинга сборки — их не было вообще.
# -D_FORTIFY_SOURCE=2 требует включённой оптимизации, поэтому идёт вместе с -O2.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 -std=c++17")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pie -Wl,-z,relro,-z,now")

# ASan / UBSan sanitizer build option per security guidelines §2
option(ENABLE_ASAN "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
if(ENABLE_ASAN)
    message(STATUS "Enabling AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan)")
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -g)
    add_link_options(-fsanitize=address,undefined)
endif()

set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY 1)
set(CMAKE_USE_WIN32_THREADS_INIT 0)
set(CMAKE_USE_PTHREADS_INIT 1)
find_package(Threads REQUIRED)

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

# Component 3 (DPI bypass) shared sources
set(DPI_SOURCES
    port_hopper.cpp
    protocol_mimicry.cpp
    traffic_shaper.cpp
    chaff_engine.cpp
    illusion_prebypass.cpp
    blackhole_responder.cpp
    network_security.cpp
)

add_executable(aegis_server server.cpp tun_interface.cpp ip_router.cpp handshake.cpp ip_pool.cpp nat_manager.cpp ${DPI_SOURCES})
target_include_directories(aegis_server PRIVATE ${SQLITE3_INCLUDE_DIRS})
target_link_libraries(aegis_server PRIVATE OpenSSL::Crypto ${SQLITE3_LIBRARIES} Threads::Threads)

add_executable(aegis_client client.cpp tun_interface.cpp ip_router.cpp handshake.cpp ip_pool.cpp nat_manager.cpp ${DPI_SOURCES})
target_link_libraries(aegis_client PRIVATE OpenSSL::Crypto Threads::Threads)

add_executable(aegis_test test_runner.cpp tun_interface.cpp ip_router.cpp handshake.cpp ip_pool.cpp nat_manager.cpp ${DPI_SOURCES})
target_link_libraries(aegis_test PRIVATE OpenSSL::Crypto Threads::Threads)
