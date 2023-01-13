# nginx-quic-stack

This project is developed by BVC (Bilibili Video Cloud team). It provides a suite of easy-to-use HTTP/3(QUIC) protocol api for any server application who plans to use QUIC as network protocol. We also provide another example project [nginx-quic-module](https://github.com/bilibili/nginx_quic_module) to illustra the usage of the quic stack in nginx server.

## Getting Started

### Prerequisite

This project requires quiche(https://github.com/bilibili/quiche) to compile.
```bash
git submodule update --init --recursive
```

### Build

```bash
mkdir build && cd build
cmake .. && make
cd -
```
You will have libngxquicstack.so generated in the build directory once the project was successfully compiled.

### Use

Simply copy the library and api header file under utils directory to equip your server with QUIC protocol.
