#!/bin/bash -x

apt update && apt install -y libpcap-dev
ldconfig

# build srtpdecrypt x86_64
mkdir -p dist
cd src
gcc aes.c analyze.c base64.c decrypt.c extract.c file.c hex.c srtpdecrypt.c usage-and-help.c -o ../dist/rtptool -lpcap

