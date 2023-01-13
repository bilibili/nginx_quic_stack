CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

PROJECT(ngxquicstack)

SET(CMAKE_POSITION_INDEPENDENT_CODE ON)
SET(CMAKE_CXX_FLAGS_DEBUG "$ENV{CXXFLAGS} -O0 -Wall -g2 -ggdb -fPIC")
#SET(CMAKE_BUILD_TYPE "Debug")
#SET(BUILD_SHARED_LIBS OFF)
SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=unused-result -fPIC")

ADD_SUBDIRECTORY(${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche quiche)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_BINARY_DIR}
    ${CMAKE_BINARY_DIR}/quiche
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/gquiche
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/googleurl
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/third_party/boringssl/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/quiche/third_party/spdlog/include
)

message("BINARY_SRC = ${CMAKE_CURRENT_BINARY_DIR}")

SET(NGINX_QUIC_STACK_SRCS
    third_party/quiche/base/files/file_path.cc
    third_party/quiche/base/files/file_path_constants.cc
    third_party/quiche/base/files/file_util.cc
    third_party/quiche/base/files/file_util_posix.cc
    third_party/quiche/base/strings/stringprintf.cc
    src/net/base/escape.cc
    src/net/base/parse_number.cc
    src/http_parser/http_parser.c
    src/http_parser/http_request_headers.cc
    src/http_parser/http_response_headers.cc
    src/http_parser/http_util.cc
    src/http_parser/http_byte_range.cc
    src/tQuicStack.cc
    src/tQuicAlarmFactory.cc
    src/tQuicClock.cc
    src/tQuicProofSource.cc
    src/tQuicConnectionHelper.cc
    src/tQuicCryptoServerStream.cc
    src/tQuicDispatcher.cc
    src/tQuicServerSession.cc
    src/tQuicServerStream.cc
)

# Build bvc quic server binaries.
ADD_LIBRARY(ngxquicstack SHARED ${NGINX_QUIC_STACK_SRCS})
TARGET_LINK_LIBRARIES(ngxquicstack -static-libstdc++
    quiche
)
