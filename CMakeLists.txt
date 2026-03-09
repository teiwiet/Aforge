cmake_minimum_required(VERSION 3.10)

project(fwscan)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

add_executable(fwscan
    src/main.cpp
    src/extractor.cpp
    src/walker.cpp
    src/scanner.cpp
    src/analyzer.cpp
)
