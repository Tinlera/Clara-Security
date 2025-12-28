cmake_minimum_required(VERSION 3.18)
project(clara_security VERSION 0.2.0 LANGUAGES CXX)

# C++17 standardı
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Android NDK ayarları
if(ANDROID)
    set(CMAKE_ANDROID_STL_TYPE c++_shared)
    add_definitions(-DANDROID)
    
    # Android NDK'dan log library
    find_library(log-lib log)
    
    # Android yerleşik kütüphaneleri
    # SQLite3 - Android'de mevcuttur
    # OpenSSL/BoringSSL - Android'de mevcuttur ama doğrudan erişilemez
    # Bu yüzden koşullu derleme kullanıyoruz
    add_definitions(-DANDROID_NO_EXTERNAL_LIBS)
else()
    # Desktop build için normal paketler
    find_package(SQLite3 QUIET)
    find_package(OpenSSL QUIET)
    find_package(CURL QUIET)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBZIP libzip)
    endif()
endif()

# Compiler flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2 -fPIC")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -DNDEBUG")

# Include dizinleri
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/orchestrator/include
    ${CMAKE_SOURCE_DIR}/security_core/include
    ${CMAKE_SOURCE_DIR}/privacy_core/include
    ${CMAKE_SOURCE_DIR}/app_manager/include
    ${CMAKE_SOURCE_DIR}/shared/include
)

# Thread desteği
find_package(Threads REQUIRED)

# =============================================================================
# Shared Library
# =============================================================================
set(SHARED_SOURCES
    src/ai_engine.cpp
    src/clara_daemon.cpp
)

add_library(clara_shared STATIC ${SHARED_SOURCES})
target_link_libraries(clara_shared Threads::Threads)

# =============================================================================
# Orchestrator Daemon
# =============================================================================
add_executable(clara_orchestrator
    orchestrator/src/orchestrator.cpp
    orchestrator/src/main.cpp
)

target_link_libraries(clara_orchestrator
    clara_shared
    Threads::Threads
    ${CMAKE_DL_LIBS}
)

# =============================================================================
# Security Core Daemon
# =============================================================================
set(SECURITY_CORE_SOURCES
    src/sms_monitor.cpp
    src/file_monitor.cpp
    src/network_monitor.cpp
    security_core/src/messenger_monitor.cpp
    security_core/src/keylogger_detector.cpp
    security_core/src/overlay_detector.cpp
    security_core/src/clipboard_guard.cpp
    security_core/src/screen_capture_detector.cpp
    security_core/src/wifi_auditor.cpp
    trust_engine/src/trust_engine.cpp
    security_core/src/main.cpp
)

add_executable(clara_security_core ${SECURITY_CORE_SOURCES})

target_link_libraries(clara_security_core
    clara_shared
    Threads::Threads
)

if(SQLite3_FOUND)
    target_link_libraries(clara_security_core SQLite::SQLite3)
    target_compile_definitions(clara_security_core PRIVATE HAVE_SQLITE3)
endif()

if(OpenSSL_FOUND)
    target_link_libraries(clara_security_core OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(clara_security_core PRIVATE HAVE_OPENSSL)
endif()

if(LIBZIP_FOUND AND NOT ANDROID)
    target_include_directories(clara_security_core PRIVATE ${LIBZIP_INCLUDE_DIRS})
    target_link_libraries(clara_security_core ${LIBZIP_LIBRARIES})
    target_compile_definitions(clara_security_core PRIVATE HAVE_LIBZIP)
endif()

# =============================================================================
# Privacy Core Daemon
# =============================================================================
set(PRIVACY_CORE_SOURCES
    privacy_core/src/permission_watcher.cpp
    privacy_core/src/tracker_blocker.cpp
    privacy_core/src/network_firewall.cpp
    privacy_core/src/main.cpp
)

add_executable(clara_privacy_core ${PRIVACY_CORE_SOURCES})

target_link_libraries(clara_privacy_core
    clara_shared
    Threads::Threads
)

if(CURL_FOUND)
    target_link_libraries(clara_privacy_core CURL::libcurl)
    target_compile_definitions(clara_privacy_core PRIVATE HAVE_CURL)
endif()

# =============================================================================
# App Manager Daemon
# =============================================================================
set(APP_MANAGER_SOURCES
    app_manager/src/app_lock.cpp
    app_manager/src/root_hider.cpp
    app_manager/src/main.cpp
)

add_executable(clara_app_manager ${APP_MANAGER_SOURCES})

target_link_libraries(clara_app_manager
    clara_shared
    Threads::Threads
)

if(OpenSSL_FOUND)
    target_link_libraries(clara_app_manager OpenSSL::SSL OpenSSL::Crypto)
endif()

# =============================================================================
# CLI Tool
# =============================================================================
add_executable(clara_cli
    tools/cli/main.cpp
)

target_link_libraries(clara_cli
    Threads::Threads
)

# =============================================================================
# Kurulum
# =============================================================================
install(TARGETS 
    clara_orchestrator 
    clara_security_core 
    clara_privacy_core 
    clara_app_manager
    clara_cli
    RUNTIME DESTINATION system/bin
)

install(FILES ../config.json
    DESTINATION system/etc/clara
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/../models/
    DESTINATION system/etc/clara/models
    OPTIONAL
)

# =============================================================================
# Android NDK Cross-Compile
# =============================================================================
if(DEFINED ANDROID_NDK)
    message(STATUS "Building for Android with NDK: ${ANDROID_NDK}")
    
    # Android spesifik ayarlar
    add_definitions(-D__ANDROID_API__=${ANDROID_NATIVE_API_LEVEL})
    
    # SQLite Android'de built-in
    target_compile_definitions(clara_security_core PRIVATE HAVE_SQLITE3)
endif()

# =============================================================================
# Test (Opsiyonel)
# =============================================================================
option(BUILD_TESTS "Build tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
