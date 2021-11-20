include_guard()

# Change these defaults to point to your infrastructure if desired
set(CMKR_REPO "https://github.com/build-cpp/cmkr" CACHE STRING "cmkr git repository" FORCE)
set(CMKR_TAG "archive_7c7144b1" CACHE STRING "cmkr git tag (this needs to be available forever)" FORCE)

# Set these from the command line to customize for development/debugging purposes
set(CMKR_EXECUTABLE "" CACHE FILEPATH "cmkr executable")
set(CMKR_SKIP_GENERATION OFF CACHE BOOL "skip automatic cmkr generation")

# Disable cmkr if generation is disabled
if(DEFINED ENV{CI} OR CMKR_SKIP_GENERATION OR CMKR_BUILD_SKIP_GENERATION)
    message(STATUS "[cmkr] Skipping automatic cmkr generation")
    unset(CMKR_BUILD_SKIP_GENERATION CACHE)
    macro(cmkr)
    endmacro()
    return()
endif()

# Disable cmkr if no cmake.toml file is found
if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake.toml")
    message(AUTHOR_WARNING "[cmkr] Not found: ${CMAKE_CURRENT_SOURCE_DIR}/cmake.toml")
    macro(cmkr)
    endmacro()
    return()
endif()

# Convert a Windows native path to CMake path
if(CMKR_EXECUTABLE MATCHES "\\\\")
    string(REPLACE "\\" "/" CMKR_EXECUTABLE_CMAKE "${CMKR_EXECUTABLE}")
    set(CMKR_EXECUTABLE "${CMKR_EXECUTABLE_CMAKE}" CACHE FILEPATH "" FORCE)
    unset(CMKR_EXECUTABLE_CMAKE)
endif()

# Helper macro to execute a process (COMMAND_ERROR_IS_FATAL ANY is 3.19 and higher)
function(cmkr_exec)
    execute_process(COMMAND ${ARGV} RESULT_VARIABLE CMKR_EXEC_RESULT)
    if(NOT CMKR_EXEC_RESULT EQUAL 0)
        message(FATAL_ERROR "cmkr_exec(${ARGV}) failed (exit code ${CMKR_EXEC_RESULT})")
    endif()
endfunction()

# Windows-specific hack (CMAKE_EXECUTABLE_PREFIX is not set at the moment)
if(WIN32)
    set(CMKR_EXECUTABLE_NAME "cmkr.exe")
else()
    set(CMKR_EXECUTABLE_NAME "cmkr")
endif()

# Use cached cmkr if found
set(CMKR_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/_cmkr_${CMKR_TAG}")
set(CMKR_CACHED_EXECUTABLE "${CMKR_DIRECTORY}/bin/${CMKR_EXECUTABLE_NAME}")

if(NOT CMKR_CACHED_EXECUTABLE STREQUAL CMKR_EXECUTABLE AND CMKR_EXECUTABLE MATCHES "^${CMAKE_CURRENT_BINARY_DIR}/_cmkr")
    message(AUTHOR_WARNING "[cmkr] Upgrading '${CMKR_EXECUTABLE}' to '${CMKR_CACHED_EXECUTABLE}'")
    unset(CMKR_EXECUTABLE CACHE)
endif()

if(CMKR_EXECUTABLE AND EXISTS "${CMKR_EXECUTABLE}")
    message(VERBOSE "[cmkr] Found cmkr: '${CMKR_EXECUTABLE}'")
elseif(CMKR_EXECUTABLE AND NOT CMKR_EXECUTABLE STREQUAL CMKR_CACHED_EXECUTABLE)
    message(FATAL_ERROR "[cmkr] '${CMKR_EXECUTABLE}' not found")
else()
    set(CMKR_EXECUTABLE "${CMKR_CACHED_EXECUTABLE}" CACHE FILEPATH "Full path to cmkr executable" FORCE)
    message(VERBOSE "[cmkr] Bootstrapping '${CMKR_EXECUTABLE}'")
    
    message(STATUS "[cmkr] Fetching cmkr...")
    if(EXISTS "${CMKR_DIRECTORY}")
        cmkr_exec("${CMAKE_COMMAND}" -E rm -rf "${CMKR_DIRECTORY}")
    endif()
    find_package(Git QUIET REQUIRED)
    cmkr_exec("${GIT_EXECUTABLE}"
        clone
        --config advice.detachedHead=false
        --branch ${CMKR_TAG}
        --depth 1
        ${CMKR_REPO}
        "${CMKR_DIRECTORY}"
    )
    message(STATUS "[cmkr] Building cmkr...")
    cmkr_exec("${CMAKE_COMMAND}"
        --no-warn-unused-cli
        "${CMKR_DIRECTORY}"
        "-B${CMKR_DIRECTORY}/build"
        "-DCMAKE_BUILD_TYPE=Release"
        "-DCMAKE_INSTALL_PREFIX=${CMKR_DIRECTORY}"
        "-DCMKR_GENERATE_DOCUMENTATION=OFF"
    )
    cmkr_exec("${CMAKE_COMMAND}"
        --build "${CMKR_DIRECTORY}/build"
        --config Release
        --parallel
    )
    cmkr_exec("${CMAKE_COMMAND}"
        --install "${CMKR_DIRECTORY}/build"
        --config Release
        --prefix "${CMKR_DIRECTORY}"
        --component cmkr
    )
    if(NOT EXISTS ${CMKR_EXECUTABLE})
        message(FATAL_ERROR "[cmkr] Failed to bootstrap '${CMKR_EXECUTABLE}'")
    endif()
    cmkr_exec("${CMKR_EXECUTABLE}" version)
    message(STATUS "[cmkr] Bootstrapped ${CMKR_EXECUTABLE}")
endif()
execute_process(COMMAND "${CMKR_EXECUTABLE}" version
    RESULT_VARIABLE CMKR_EXEC_RESULT
)
if(NOT CMKR_EXEC_RESULT EQUAL 0)
    message(FATAL_ERROR "[cmkr] Failed to get version, try clearing the cache and rebuilding")
endif()

# This is the macro that contains black magic
macro(cmkr)
    # When this macro is called from the generated file, fake some internal CMake variables
    get_source_file_property(CMKR_CURRENT_LIST_FILE "${CMAKE_CURRENT_LIST_FILE}" CMKR_CURRENT_LIST_FILE)
    if(CMKR_CURRENT_LIST_FILE)
        set(CMAKE_CURRENT_LIST_FILE "${CMKR_CURRENT_LIST_FILE}")
        get_filename_component(CMAKE_CURRENT_LIST_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)
    endif()

    # File-based include guard (include_guard is not documented to work)
    get_source_file_property(CMKR_INCLUDE_GUARD "${CMAKE_CURRENT_LIST_FILE}" CMKR_INCLUDE_GUARD)
    if(NOT CMKR_INCLUDE_GUARD)
        set_source_files_properties("${CMAKE_CURRENT_LIST_FILE}" PROPERTIES CMKR_INCLUDE_GUARD TRUE)

        file(SHA256 "${CMAKE_CURRENT_LIST_FILE}" CMKR_LIST_FILE_SHA256_PRE)

        # Generate CMakeLists.txt
        cmkr_exec("${CMKR_EXECUTABLE}" gen
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        )

        file(SHA256 "${CMAKE_CURRENT_LIST_FILE}" CMKR_LIST_FILE_SHA256_POST)

        # Delete the temporary file if it was left for some reason
        set(CMKR_TEMP_FILE "${CMAKE_CURRENT_SOURCE_DIR}/CMakerLists.txt")
        if(EXISTS "${CMKR_TEMP_FILE}")
            file(REMOVE "${CMKR_TEMP_FILE}")
        endif()

        if(NOT CMKR_LIST_FILE_SHA256_PRE STREQUAL CMKR_LIST_FILE_SHA256_POST)
            # Copy the now-generated CMakeLists.txt to CMakerLists.txt
            # This is done because you cannot include() a file you are currently in
            configure_file(CMakeLists.txt "${CMKR_TEMP_FILE}" COPYONLY)
            
            # Add the macro required for the hack at the start of the cmkr macro
            set_source_files_properties("${CMKR_TEMP_FILE}" PROPERTIES
                CMKR_CURRENT_LIST_FILE "${CMAKE_CURRENT_LIST_FILE}"
            )
            
            # 'Execute' the newly-generated CMakeLists.txt
            include("${CMKR_TEMP_FILE}")
            
            # Delete the generated file
            file(REMOVE "${CMKR_TEMP_FILE}")
            
            # Do not execute the rest of the original CMakeLists.txt
            return()
        endif()
        # Resume executing the unmodified CMakeLists.txt
    endif()
endmacro()
