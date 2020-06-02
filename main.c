/*

 A simple hash cracker.

 Notes:
 - Every hash function returns a string which must be freed by the caller;

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define BUFFER_SIZE 65535
#define ARGUMENTS_NUMBER 1+2*2

char *digest_to_hex(unsigned char *, int);
char *md5(char *);
char *sha1(char *);
char *sha256(char *);
char *sha512(char *);

int main(int argc, char *argv[]) {

	// Check for the correct number of arguments and if not print the usage
	if(argc-1 != ARGUMENTS_NUMBER) {
		printf("Usage:\n");
		printf("%s -d DICT_FILENAME -m MODE_NUMBER HASH\n\n", argv[0]);
		printf("  Options:\n");
		printf("   -d  Specify a file containing the wordlist split by newline\n");
		printf("   -m  0: md5, 1: sha1, 2: sha256, 3: sha512\n");
		return 1;
	}

	// Find and store the arguments
	char *dict_filename, *hash;
	int hash_mode;
	for(int i=1; i<argc; i++) {

		// Find the dictionary filename
		if(strcmp("-d", argv[i]) == 0) {
			dict_filename = malloc(strlen(argv[i+1])+1);
			strcpy(dict_filename, argv[i+1]);
			i++;		// Skip the value of the argument

		// Find the hashing algorithm to use
		} else if(strcmp("-m", argv[i]) == 0) {
			hash_mode = atoi(argv[i+1]);
			i++;

		// Find the hash string
		} else {
			hash = malloc(strlen(argv[i])+1);
			strcpy(hash, argv[i]);
		}
	}

	// Make the hash lowercase for comparison
	for(int i=0; i<strlen(hash); i++) {
		hash[i] = tolower(hash[i]);
	}

	FILE *dictionary = fopen(dict_filename, "r");
	if(! dictionary) {
		printf("An error has occurred while opening the dictionary file.\n");
		return 1;
	}

	char *buffer = malloc(BUFFER_SIZE + 1);
	while(! feof(dictionary)) {
		fgets(buffer, BUFFER_SIZE, dictionary);

		// Remove the \n if it's the last character
		if(buffer[strlen(buffer)-1] == '\n') {
			buffer[strlen(buffer)-1] = '\0';
		}

		// Calculate the current hash and check it against the argument hash
		char *_current_hash;
		switch(hash_mode) {
			case 0:
				_current_hash = md5(buffer);
				break;
			case 1:
				_current_hash = sha1(buffer);
				break;
			case 2:
				_current_hash = sha256(buffer);
				break;
			case 3:
				_current_hash = sha512(buffer);
				break;
		}
		if(strcmp(_current_hash, hash) == 0) {
			printf("[+] Found | %s\n", buffer);
			return 0;
		}
		free(_current_hash);
	}
}

char *digest_to_hex(unsigned char *digest, int len) {
	/*
	 Converts the `len` bytes digest to an hexadecimal
	 string ending with NUL.
	*/

	char *hex_digest = malloc(len*2 + 1);
	for(int i=0; i<len; i++) {
		sprintf(hex_digest + i*2, "%02x", (unsigned int) digest[i]);
	}

	return hex_digest;
}

char *md5(char *string) {
	unsigned char digest[MD5_DIGEST_LENGTH];

	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update(&context, string, strlen(string));
	MD5_Final(digest, &context);

	return digest_to_hex(digest, MD5_DIGEST_LENGTH);
}

char *sha1(char *string) {
	unsigned char digest[SHA_DIGEST_LENGTH];

	SHA_CTX context;
	SHA1_Init(&context);
	SHA1_Update(&context, string, strlen(string));
	SHA1_Final(digest, &context);

	return digest_to_hex(digest, SHA_DIGEST_LENGTH);
}

char *sha256(char *string) {
	unsigned char digest[SHA256_DIGEST_LENGTH];

	SHA256_CTX context;
	SHA256_Init(&context);
	SHA256_Update(&context, string, strlen(string));
	SHA256_Final(digest, &context);

	return digest_to_hex(digest, SHA256_DIGEST_LENGTH);
}

char *sha512(char *string) {
	unsigned char digest[SHA512_DIGEST_LENGTH];

	SHA512_CTX context;
	SHA512_Init(&context);
	SHA512_Update(&context, string, strlen(string));
	SHA512_Final(digest, &context);

	return digest_to_hex(digest, SHA512_DIGEST_LENGTH);
}