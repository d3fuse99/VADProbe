cmake_minimum_required(VERSION 3.20)
project(HollowTrace CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

add_executable(HollowTrace
    src/main.cpp
    src/Privileges.cpp
    src/Dumper.cpp
    src/Heuristics.cpp
    src/Scanner.cpp
)

target_link_libraries(HollowTrace PRIVATE
    psapi.lib
    advapi32.lib
)