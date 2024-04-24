cmake_minimum_required(VERSION 2.8.9)
project(zlib_functest)
# Download and unpack googletest at configure time
configure_file(CMakeLists.txt.in googletest-download/CMakeLists.txt)
execute_process(COMMAND "${CMAKE_COMMAND}" -G "${CMAKE_GENERATOR}" .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download"
)
execute_process(COMMAND "${CMAKE_COMMAND}" --build .
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/googletest-download"
)

# Prevent GoogleTest from overriding our compiler/linker options
# when building with Visual Studio
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

# Add googletest directly to our build. This adds the following targets:
# gtest, gtest_main, gmock and gmock_main
add_subdirectory("${CMAKE_BINARY_DIR}/googletest-src"
                 "${CMAKE_BINARY_DIR}/googletest-build"
)

# The gtest/gmock targets carry header search path dependencies
# automatically when using CMake 2.8.11 or later. Otherwise we
# have to add them here ourselves.
if(CMAKE_VERSION VERSION_LESS 2.8.11)
    include_directories("${gtest_SOURCE_DIR}/include"
                        "${gmock_SOURCE_DIR}/include"
                        
    )
endif()

option(USE_DEBUG "DEBUG MODE" OFF)
if (USE_DEBUG)
    message("---------DEBUG MODE ON---------")
    add_definitions(-DZ_DEBUG)
endif()

option(KP920B "KP920B PLATFORM" OFF)
if (KP920B)
    message("---------KP920B ON---------")
    add_definitions(-DKP920B)
endif()

option(PERF "DO PERF CASE" OFF)
if (PERF)
    message("---------PERF ON---------")
    add_definitions(-DPERF)
endif()

option(TEST_OPEN "TEST_OPEN" OFF)
if (TEST_OPEN)
    message("---------TEST_OPEN ON---------")
    add_definitions(-DTEST_OPEN)
    include_directories("
        ${CMAKE_CURRENT_SOURCE_DIR}/../include"
    )
    add_executable(zlib_functest main.cpp)
    target_link_libraries(zlib_functest gtest
                                        gtest_main
                                        z
    )
else()
    include_directories("
        ${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "/usr/local/kaezip/include"
    )
    find_library(KAEZIP_LIB kaezip PATHS "/usr/local/kaezip/lib")
    # 这里改成自己的运行文件
    add_executable(zlib_functest main.cpp)
    
    link_directories(/usr/local/kaezip/lib/)
    
    # 链接库是必须的
    target_link_libraries(zlib_functest gtest
                                        gtest_main
                                        z
                                        ${KAEZIP_LIB}
    )
endif()

enable_testing()