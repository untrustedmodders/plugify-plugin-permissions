cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(POLICY CMP0092)
    cmake_policy(SET CMP0092 NEW) # Don't add -W3 warning level by default.
endif()


file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.txt" VERSION_FILE_CONTENTS)
string(STRIP "${VERSION_FILE_CONTENTS}" VERSION_FILE_CONTENTS)
set(PLUGIN_VERSION "${VERSION_FILE_CONTENTS}" CACHE STRING "Set version name")
set(PLUGIN_PACKAGE "plugify-permissions" CACHE STRING "Set package name")
string(REPLACE "v" "" PLUGIN_VERSION "${PLUGIN_VERSION}")
string(REGEX REPLACE "[.+-]" ";" PLUGIN_VERSION_LIST ${PLUGIN_VERSION})
list(GET PLUGIN_VERSION_LIST 0 PLUGIN_VERSION_MAJOR)
list(GET PLUGIN_VERSION_LIST 1 PLUGIN_VERSION_MINOR)
list(GET PLUGIN_VERSION_LIST 2 PLUGIN_VERSION_PATCH)

project(plugify-permissions
        VERSION "${PLUGIN_VERSION_MAJOR}.${PLUGIN_VERSION_MINOR}.${PLUGIN_VERSION_PATCH}"
        DESCRIPTION "Minimalistic permissions core"
        HOMEPAGE_URL "https://github.com/untrustedmodders/plugify-permissions"
        LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

#
# Format
#
include(CompatFormat)

#
# Plugin
#
set(PLUGIN_SOURCES "plugin.cpp"
        api/groupManager.h
        api/userManager.h
        api/basic.h
        api/groupManager.cpp
        api/userManager.cpp
        api/xxhash.cpp)

add_library(${PROJECT_NAME} SHARED ${PLUGIN_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /WX)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wextra -Wshadow -Wconversion -Wpedantic -Werror)
endif()

if(UNIX AND NOT APPLE)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _GLIBCXX_USE_CXX11_ABI=0)
    target_link_libraries(${PROJECT_NAME} PRIVATE -static-libstdc++ -static-libgcc)
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE
        PLUGIFY_FORMAT_SUPPORT=$<BOOL:${COMPILER_SUPPORTS_FORMAT}>
        PLUGIFY_IS_DEBUG=$<STREQUAL:${CMAKE_BUILD_TYPE},Debug>)
if(NOT COMPILER_SUPPORTS_FORMAT)
    target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt-header-only)
endif()

include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME} EXPORT_MACRO_NAME PLUGIN_API EXPORT_FILE_NAME ${CMAKE_BINARY_DIR}/exports/plugin_export.h)
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_BINARY_DIR}/exports)

if(APPLE)
    target_link_libraries(${PROJECT_NAME} PRIVATE "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/sym/exported_symbols.lds")
elseif(UNIX)
    target_link_libraries(${PROJECT_NAME} PRIVATE "-Wl,--version-script,${CMAKE_CURRENT_SOURCE_DIR}/sym/version_script.lds")
endif()

configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/plugify-permissions.pplugin.in
        ${CMAKE_CURRENT_BINARY_DIR}/plugify-permissions.pplugin
)