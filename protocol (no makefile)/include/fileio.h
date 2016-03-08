#ifndef FILEIO_H
#define FILEIO_H

#include "constant.h"

// #define current_stamp(a) asm volatile("rdtsc":"=a"(((unsigned int *)(a))[0]),"=d"(((unsigned int *)a)[1]))
#define current_stamp(a)    __asm__ __volatile__("rdtsc":"=a"(((unsigned int *)(a))[0]),"=d"(((unsigned int *)a)[1]));

void writePublicKeyFile(const char *fileName, char *data);
char* readECCPublicKeyFile(const char *fileName);

struct timeval timingStart();
void timingEnd(struct timeval startTime, char* funcName);

// struct timeval timingStart(clock_t *startClock);
// void timingEnd(struct timeval startTime, clock_t startClock, char* funcName);

#endif /* FILEIO_H */