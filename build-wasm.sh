#!/bin/bash -x

# verify Emscripten version
emcc -v

wget https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz
tar xf libpcap-1.9.1.tar.gz && cd libpcap-1.9.1
# emconfigure ./configure && emmake make
cd ..

# build srtpdecrypt.wasm
mkdir -p wasm/dist
cd src
ARGS=(
  -O3
  -s WASM=1
  -s ERROR_ON_UNDEFINED_SYMBOLS=0
  -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap"]' 
  -I. -I../libpcap-1.9.1
  -o ../wasm/dist/rtptool.js aes.c analyze.c base64.c decrypt.c extract.c file.c hex.c srtpdecryptwasm.c usage-and-help.c
)
emcc "${ARGS[@]}"
