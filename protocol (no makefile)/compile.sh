#!/bin/sh

clientA="a.exe"
clientB="b.exe"

GCC_OPTIONS="-Wall"

INCLUDE_DIR="-I/home/debian/fullprotocol/include 
			-I/usr/local/include/cryptoauth-0.2 
			-I/usr/include/glib-2.0 
			-I/usr/lib/arm-linux-gnueabihf/glib-2.0/include"

LIBRARY_DIR="-L/usr/local/lib/libcryptoauth"
LIBRARIES="-lcryptoauth-0.2 -ltspi -lssl -lcrypto -lglib-2.0"

OTHER_C_FILES="tpm.c base64.c aes.c ecc.c socket.c serialization.c certificate.c"

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

#gcc clientA.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o $clientA 

#gcc clientB.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o $clientB 

#gcc genrsakey.c base64.c $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o genkey.exe 

#gcc gencert.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o cagen.exe

#gcc CAsigncert.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o gencsr.exe

#gcc signCSR.c $OTHER_C_FILES $INCLUDE_DIR $LIBRARY_DIR $LIBRARIES $GCC_OPTIONS -o signcsr.exe
