#include "codelock.h"

uint8_t rand_initialized;

/*
 * Linux integration
 */
#ifdef CL_LINUX

#include <fcntl.h>
#include <unistd.h>

#define RAND_FILE_PATH "/dev/urandom"

uint8_t random_fd = -1;

cl_retval cl_init_rand() {

	random_fd = open(RAND_FILE_PATH, O_RDONLY);
	if (random_fd < 0) {
		random_fd = -1;
		return CL_SYSTEM_ERROR;
	}

	rand_initialized = 1;
	return CL_OK;
}

uint32_t cl_get_random(uint32_t from, uint32_t to) {

	uint32_t result;
	char success = 0;

	while (!success) {
		read(random_fd, &result, 2);
		if (result >= from && result <= to)
			success = 1;
	}

	return result;
}

uint8_t cl_rand8() {
	uint8_t result;
	read(random_fd, &result, 1);
	return result;
}

cl_retval cl_rand_block(uint8_t * result, uint16_t blkbytes, char force_odd) {
	if (read(random_fd, result, blkbytes) != blkbytes)
		return CL_SYSTEM_ERROR;

	if (force_odd) {
		uint16_t i;
		uint16_t limit = 0;
		uint8_t parity = 0;
		for (i = 0; i < blkbytes - 1; ++i) {
			parity ^= result[i];
		}
		uint8_t odd;	
		do {
		odd = parity ^ result[blkbytes - 1];
		odd ^= odd >> 4;
		odd ^= odd >> 2;
		odd ^= odd >> 1;
		odd &= 0x1;

		if (!odd)
			result[blkbytes - 1] = cl_rand8();

		++limit;
		} while (!odd && limit < 10000);

		if (!odd)
			return CL_FAILED;
	}
	
	return CL_OK;
}
#endif	// LINUX

/*
 * System-agnostic functions
 */
cl_retval cl_rand_errv(struct cl_errorvector * errv) {
	
	uint16_t i;
	for (i = 0; i < errv->params->t; ++i) {
		char success = 0;
		while (!success) {
			success = 1;
			errv->errors[i] = cl_get_random(0, errv->params->N0 * errv->params->M - 1);
			int j;
			for (j = 0; j < i; ++j) {
				if (errv->errors[i] == errv->errors[j]) {
					success = 0;
					break;
				}
			}
		}
	}

	cl_sort_errv(errv);
	return CL_OK;
}

cl_retval cl_rand_pc_key(struct cl_pc_key * key) {
	
	// Useful helper consts
	const uint16_t blkbytes = (key->params->M / 8) + ((key->params->M % 8) ? 1 : 0);

	uint32_t i, j;
	for (i = 0; i < key->params->N0; ++i) {
		for (j = 0; j < key->params->w0; ++j) {
			char success = 0;
			while (!success) {
				key->key[i * key->params->w0 + j] = cl_get_random(i * key->params->M, (i + 1) * key->params->M - 1);
				uint32_t k;
				success = 1;
				for (k = 0; k < j; ++k) {
					if (key->key[i * key->params->w0 + k] == key->key[i * key->params->w0 + j]) {
						success = 0;
						break;
					}
				}
			}
		}
	}
	return CL_OK;
}

