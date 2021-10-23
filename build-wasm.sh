#!/bin/bash -x
set -e
set -o pipefail

# verify Emscripten version
emcc -v

if [ ! -d "./libpcap-1.9.1" ]
then
  apt-get update && apt-get install -y flex bison
  wget https://www.tcpdump.org/release/libpcap-1.9.1.tar.gz
  tar xf libpcap-1.9.1.tar.gz
  rm -rf libpcap-1.9.1.tar.gz
  cd libpcap-1.9.1
  emconfigure ./configure --with-pcap=null && emmake make && emmake make install
  find -name "libpcap.so*" -o -name "libpcap.a"
  cd ..
fi


# build srtpdecrypt.wasm
mkdir -p wasm/dist
cd src
ARGS=(
  -O3
  -s WASM=1
  -s ERROR_ON_UNDEFINED_SYMBOLS=0
  -s EXTRA_EXPORTED_RUNTIME_METHODS='["cwrap"]'
  -s FORCE_FILESYSTEM=1
  -s ASSERTIONS=1
  -I. -I../libpcap-1.9.1
  -L../libpcap-1.9.1
  -o ../wasm/dist/rtptool.js aes.c analyze.c base64.c extract.c file.c hex.c srtpdecryptwasm.c usage-and-help.c -lpcap
)
emcc "${ARGS[@]}"
