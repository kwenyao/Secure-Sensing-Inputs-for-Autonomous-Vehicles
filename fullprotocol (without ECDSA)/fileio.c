#include "fileio.h"

void writePublicKeyFile(const char *fileName, char *data) {
	FILE *fout;
	fout = fopen(fileName, "w");
	if (fout != NULL) {
		fputs(data, fout);
		printf("%s created\n", fileName);
		fclose(fout);
	} else {
		printf("Error creating %s\n", fileName);
	}
}

char* readECCPublicKeyFile(const char *fileName) {
	FILE *fStream = fopen(fileName, "r");
	char *data = malloc(ECC_PUBKEY_LENGTH);
	fseek(fStream, 0, SEEK_SET);
	if (data) {
		fread(data, 1, ECC_PUBKEY_LENGTH, fStream);
		// printf("\nData read from %s:\n%s\n\n", fileName, data);
	} else {
		printf("Error opening %s!\n", fileName);
	}
	fclose(fStream);
	return data;
}

struct timeval timingStart() {
	struct timeval start;
	gettimeofday(&start, NULL);
	return start;
}

// struct timeval timingStart(clock_t *startClock) {
// 	struct timeval start;
// 	gettimeofday(&start, NULL);
// 	*startClock = clock();
// 	return start;
// }

void timingEnd(struct timeval startTime, char* funcName) {
	struct timeval endTime;
	gettimeofday(&endTime, NULL);
	printf("Time taken for %s = %f seconds\n",
	       funcName,
	       (double) (endTime.tv_usec - startTime.tv_usec) / 1000000 +
	       (double) (endTime.tv_sec - startTime.tv_sec));
	return;
}

// void timingEnd(struct timeval startTime, clock_t startClock, char* funcName) {
// 	struct timeval endTime;
// 	clock_t endClock = clock();
// 	clock_t clockCycles = endClock - startClock;
// 	gettimeofday(&endTime, NULL);
// 	printf("Clock cycles = %d\n", clockCycles);
// 	printf("Time taken for %s = %f seconds\n",
// 	       funcName,
// 	       (double) (endTime.tv_usec - startTime.tv_usec) / 1000000 +
// 	       (double) (endTime.tv_sec - startTime.tv_sec));
	
// 	return;
// }
