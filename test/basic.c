#include "../src/codelock.h"

#include <stdlib.h>
#include <stdio.h>

int main() {
	
	int i, j;

	struct cl_crypto_params param1 = {4801, 2, 45, 84};
	const uint_fast16_t blkbytes = (param1.M / 8) + ((param1.M % 8) ? 1 : 0);
	
	cl_init_rand();

	struct cl_pc_key sk = new_cl_pc_key(&param1);
	struct cl_gen_key pk = new_cl_gen_key(&param1);

	printf("Start gen\n");
	cl_keygen(&param1, &sk, &pk, 0);
	printf("End gen\n");

	uint8_t * msg1 = malloc(blkbytes);
	uint8_t * msg2 = malloc(blkbytes);
	uint8_t * msgs[2];
	msgs[0] = msg1;
	msgs[1] = msg2;

	printf("Start rand\n");
	cl_rand_block(msg1, blkbytes, 0);
	cl_rand_block(msg2, blkbytes, 0);
	printf("End rand\n");

	uint8_t * codeword = malloc(param1.N0 * blkbytes);
	
	printf("Start enc\n");
	cl_encode(msgs, &pk, codeword);
	printf("End enc\n");

	struct cl_errorvector errv = new_cl_errorvector(&param1);
	cl_rand_errv(&errv);

	printf("Start inflict\n");
	cl_inflict_errv(codeword, &errv);
	printf("End inflict\n");

	uint8_t * syndrome = malloc(blkbytes);
	for (i = 0; i < blkbytes; ++i)
		syndrome[i] = 0;
	printf("Start calc\n");
	cl_calc_syndrome(codeword, &sk, syndrome);
	printf("End calc\n");
	/*
	for (i = 0; i < blkbytes; ++i)
		printf("%02x ", syndrome[i]);
	*/
	
	uint8_t decoder_params[] = {5, 30, 29, 28, 27, 26, 25, 24, 25, 22, 22, 22, 22, 22, 22};
	uint8_t * found_err = malloc(param1.N0 * blkbytes);
	printf("Start decode\n");
	cl_retval status = cl_decoder_BF_fpt(syndrome, &sk, found_err, decoder_params);
	printf("End decode\n");

	if (status == CL_DECODING_FAILURE) {
		fprintf(stderr, "Decoding failed\n");
		return -1;
	}

	return 0;
}
