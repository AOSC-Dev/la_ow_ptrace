cmake_minimum_required(VERSION 3.10)
project(la_ow_ptrace)

set(CMAKE_CXX_FLAGS "-fpermissive")
add_executable(la_ow main.cpp common.c)
