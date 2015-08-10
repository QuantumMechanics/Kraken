#ifndef ED25519_H
#define ED25519_H

#include <stdlib.h>
#include <fcntl.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef unsigned char curved25519_key[32];

void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);
int ed25519_sign_open(const unsigned char *m, size_t mlen, const ed25519_public_key pk, const ed25519_signature RS);
void ed25519_sign(const unsigned char *m, size_t mlen, const ed25519_secret_key sk, const ed25519_public_key pk, ed25519_signature RS);

int ed25519_sign_open_batch(const unsigned char **m, size_t *mlen, const unsigned char **pk, const unsigned char **RS, size_t num, int *valid);

void ed25519_randombytes_unsafe(void *out, size_t count);

void curved25519_scalarmult_basepoint(curved25519_key pk, const curved25519_key e);

/*void randombytes(unsigned char* sk, unsigned int amount)
	{
	  int fd = open("/dev/urandom", O_RDONLY);
	  if(fd < 0) {
	    perror("opening random");
	    exit(1);
	  }
	  if(read(fd, sk, amount) != amount) {
	    fprintf(stderr,"Unable to get %d bytes of random", amount);
	    exit(1);
	  }
	  close(fd);
	}*/

#if defined(__cplusplus)
}
#endif

#endif // ED25519_H
