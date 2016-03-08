#!/bin/sh

clientA="a.exe"
clientB="b.exe"

INCLUDE_DIR="-I/home/debian/fullprotocol/include -I/usr/local/include/cryptoauth-0.2"
LIBRARY_DIR="-L/usr/local/lib/libcryptoauth"
LIBRARIES="-lcryptoauth-0.2 -ltspi -lssl -lcrypto"
OTHER_C_FILES="tpm.c base64.c aes.c ecc.c socket.c fileio.c"
GCC_OPTIONS="-Wall"

if [ -e "$clientA" ]
then 
	rm a.exe
	echo "$clientA deleted"
else
	echo "$clientA not found"
fi

if [ -e "$clientB" ]
then 
	rm b.exe
	echo "$clientB deleted"
else
	echo "$clientB not found"
fi

gcc clientA.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o $clientA 

gcc clientB.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o $clientB 

gcc genrsakey.c base64.c $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o genkey.exe 

gcc createcert.c $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o createcert.exe
