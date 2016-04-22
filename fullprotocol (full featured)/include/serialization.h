#ifndef SERIALIZATION_H_   /* Include guard */

#include "socket.h"

int serializeHandshake(handshake hs, BYTE* buffer);
handshake deserializeHandshake(BYTE* message, int hasNonce, int hasEcc, int hasKey);
void serializeData(message data, BYTE* buffer);
void deserializeData(BYTE *buffer, message *msg));


#endif /* serialization_H */