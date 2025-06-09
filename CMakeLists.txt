cmake_minimum_required(VERSION 4.0.2) 

set(CMAKE_CXX_COMPILER "/usr/bin/g++")
set(CMAKE_C_COMPILER "/usr/bin/gcc")

project(MP3_Scraper)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost 1.87 REQUIRED COMPONENTS system)
find_package(libev REQUIRED)

add_executable(mp3_scraper src/YTConnect.cpp)
add_executable(example src/main.cpp)

target_include_directories(mp3_scraper PRIVATE
  ${Boost_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/quiche/quiche/include)

target_link_libraries(mp3_scraper PRIVATE
  Boost::system
  libev::libev
  ${CMAKE_SOURCE_DIR}/quiche/target/release/libquiche.a)

target_include_directories(example PRIVATE
  ${Boost_INCLUDE_DIRS}
  ${CMAKE_SOURCE_DIR}/quiche/quiche/include)

target_link_libraries(example PRIVATE
  Boost::system
  libev::libev
  ${CMAKE_SOURCE_DIR}/quiche/target/release/libquiche.a)
