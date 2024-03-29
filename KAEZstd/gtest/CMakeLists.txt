cmake_minimum_required(VERSION 2.8.9)
project(zstd_functest)
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

include_directories("${gtest_SOURCE_DIR}/include"
                        "${gmock_SOURCE_DIR}/include"
                        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
                        "/usr/local/kaezstd/include/"
                        "${CMAKE_CURRENT_SOURCE_DIR}/../src"
)

find_library(KAEZSTD_LIB kaezstd PATHS "/usr/local/kaezstd/lib/")

link_directories("/usr/local/kaezstd/lib/")



# 这里改成自己的运行文件
add_executable(zstd_functest main.cpp
                             func_common.cpp
)
# 链接库是必须的
target_link_libraries(zstd_functest gtest
                                    gtest_main
                                    zstd
                                    ${KAEZSTD_LIB}
)
enable_testing()