#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <math.h>
#include <crypt.h> 


char* salt; 
char* password; // given hashed password to crack
int keySize, threads; // keysize and number of threads

struct threadArgs {
    char start;
    char end;
};

int nextCandidate(char* candidate, int size, int n){
    int reversed = 0;
    if(n == size - 1){
        if (candidate[n] == 'z'){
            candidate[n] = 'a';
            return 1;
        } else {
            candidate[n]++;
            return 0;
        }
    }

    reversed = nextCandidate(candidate, size, n+1);
    if(reversed == 1){
        if(candidate[n] == 'z'){
            candidate[n] = 'a';
            return 1;
        }
        candidate[n]++;
        return 0;
    }
}

void crack(struct crypt_data* data, int currentSize, char startChar, int charRange) {
    char candidate[currentSize];
    for(int n = 0; n < currentSize; n++) candidate[n] = 'a'; // First password to check
    candidate[0] = startChar;

    // Loop until the last character to check in a given range is reached
    int lastCharacterIndex = pow(26, currentSize - 1) * charRange;
    for(int n = 0; n < lastCharacterIndex; n++){
        char* candidateHash = crypt_r(candidate, salt, data); // Hashing a password candidate to be compared to the password we want to crack
        if(strcmp(candidateHash, password) == 0){
            printf("Password Found: %s\n", candidate);
            exit(0);
        }
        nextCandidate(candidate, currentSize, 0);
    }
}

void* threadEntry(void* args){
    struct threadArgs* argPtr = (struct threadArgs*) args;
    struct crypt_data data;
    char startCharacter = argPtr->start;
    char endCharacter = argPtr->end;
    int charRange = endCharacter - startCharacter + 1;

    for(int i = 1; i <= keySize; i++) crack(&data, i, startCharacter, charRange);
}

int main(int argc, char* argv[]){

	if(argc != 4){
        printf("Incorrect number of arguments.\nUsage: ./crack <threads> <keysize> <target> -lpthread -lcrypt -lm\n");
		return -1;
	}
    
    password = argv[3];
    threads = atoi(argv[1]);
    keySize = atoi(argv[2]);

    // Getting the salt from the given hashed password
    char saltChar[3] = {password[0], password[1], '\0'};
	salt = saltChar;

    if (keySize < 1 || keySize > 8){
        printf("Incorrect keysize. Must be between 1 and 8\n");
        return -1;
    }

    if (threads < 1){
		printf("Threads must be at least 1\n");
        return -1;
	}

    pthread_t tid[threads]; // ids for threads
    struct threadArgs args[threads]; // args for threads
    int split = 27/threads; // character split when we're using multi-threading

    args[0].start = 'a'; // starting character for the first password to check
    for(int n = 0; n < threads; n++){
        args[n].start = 'a' + split * n;

        if (threads == 1) args[n].end = 'z'; // In case, we're dealing with 1 thread
        else args[n].end = 'a' + split * (n+1) -1;
    }
    
    for(int i = 0; i < threads; i++) pthread_create(&tid[i], NULL, threadEntry, &args[i]);
    for(int i = 0; i < threads; i++) pthread_join(tid[i], NULL);

	return 0;

}

