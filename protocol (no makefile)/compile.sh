#!/bin/sh

rm a.exe
rm b.exe

#gcc main.c -I/usr/local/include/cryptoauth-0.2 -L/usr/local/lib/libcryptoauth -lcryptoauth-0.2 -ltspi -Wall -o run.exe

gcc -I/home/debian/fullprotocol/include -I/usr/local/include/cryptoauth-0.2 -L/usr/local/lib/libcryptoauth -lcryptoauth-0.2 -ltspi -lssl -lcrypto -o a.exe clientA.c tpm.c base64.c aes.c ecc.c socket.c

gcc -I/home/debian/fullprotocol/include genrsakey.c base64.c -ltspi -Wall -o genkey.exe

gcc -I/home/debian/fullprotocol/include -I/usr/local/include/cryptoauth-0.2 -L/usr/local/lib/libcryptoauth -lcryptoauth-0.2 -ltspi -lssl -lcrypto -o b.exe clientB.c tpm.c base64.c aes.c ecc.c socket.c
