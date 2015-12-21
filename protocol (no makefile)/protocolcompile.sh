#!/bin/sh

gcc main.c -I/usr/local/include/cryptoauth-0.2  -L/usr/local/lib/libcryptoauth -lcryptoauth-0.2 -ltspi -Wall -o run.exe
