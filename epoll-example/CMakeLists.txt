cmake_minimum_required(VERSION 3.17)
project(epoll_example C)

set(CMAKE_C_STANDARD 11)

add_executable(epoll_example
        epoll.c)
