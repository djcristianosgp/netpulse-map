cmake_minimum_required(VERSION 3.20)
project(netpulse VERSION 1.12.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(sqlite3 STATIC third_party/sqlite/sqlite3.c)
target_compile_definitions(sqlite3 PRIVATE SQLITE_THREADSAFE=1)
target_include_directories(sqlite3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite)

set(NETPULSE_CORE_SOURCES
  src/core/json_lite.cpp
  src/security/auth_manager.cpp
  src/security/audit_log.cpp
  src/security/rate_limiter.cpp
  src/security/tls_context.cpp
  src/storage/sqlite_db.cpp
  src/api/api_router.cpp
  src/api/prometheus_openapi.cpp
  src/net_monitor.cpp
  src/geo_dns.cpp
  src/ws_server.cpp
  src/updater.cpp
  src/service_monitor.cpp
  src/settings_store.cpp
  src/mmdb_reader.cpp
  src/traceroute.cpp
  src/history_store.cpp
  src/quality/network_quality_engine.cpp
  src/network/interface_monitor.cpp
  src/discovery/discovery_engine.cpp
  src/discovery/topology_builder.cpp
  src/intelligence/intelligence_engine.cpp
  src/notifications/notification_engine.cpp
  src/actions.cpp
  src/tray_host.cpp
)

add_executable(netpulse
  src/main.cpp
  ${NETPULSE_CORE_SOURCES}
)

target_include_directories(netpulse PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(netpulse PRIVATE NETPULSE_VERSION="${PROJECT_VERSION}")

if(WIN32)
  target_compile_options(netpulse PRIVATE /W4 /O2 /utf-8)
  target_sources(netpulse PRIVATE src/netpulse.rc)
  target_link_libraries(netpulse PRIVATE sqlite3 ws2_32 iphlpapi winhttp bcrypt crypt32 secur32 shell32 advapi32 user32)
  set_target_properties(netpulse PROPERTIES LINK_FLAGS "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
else()
  find_package(OpenSSL REQUIRED)
  find_package(Threads REQUIRED)
  target_compile_options(netpulse PRIVATE -O2 -Wall -Wextra)
  target_link_libraries(netpulse PRIVATE sqlite3 OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS})
endif()

enable_testing()
add_executable(test_core
  tests/test_core.cpp
  ${NETPULSE_CORE_SOURCES}
)
target_include_directories(test_core PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(test_core PRIVATE NETPULSE_VERSION="${PROJECT_VERSION}")

if(WIN32)
  target_compile_options(test_core PRIVATE /W4 /O2 /utf-8)
  target_link_libraries(test_core PRIVATE sqlite3 ws2_32 iphlpapi winhttp bcrypt crypt32 secur32 shell32 advapi32 user32)
else()
  target_compile_options(test_core PRIVATE -O2 -Wall -Wextra)
  target_link_libraries(test_core PRIVATE sqlite3 OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS})
endif()

add_test(NAME NetPulseCoreAndSecurityTests COMMAND test_core)
