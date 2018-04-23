#include "../src/codelock.h"

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char ** args) {
	
	int n_errs;
	// read params
	if (argc < 2) {
		n_errs = 84;	
	} else {
		sscanf(args[1], "%i", &n_errs);
	}
	int i, j, k;

	struct cl_crypto_params param1 = {4801, 2, 45, n_errs};
	const uint_fast16_t blkbytes = (param1.M / 8) + ((param1.M % 8) ? 1 : 0);
	
	cl_init_rand();

	struct cl_pc_key sk = new_cl_pc_key(&param1);
	struct cl_gen_key pk = new_cl_gen_key(&param1);
	uint8_t * msg1 = malloc(blkbytes);
	uint8_t * msg2 = malloc(blkbytes);
	uint8_t * msgs[2];
	msgs[0] = msg1;
	msgs[1] = msg2;
	uint8_t * codeword = malloc(param1.N0 * blkbytes);
	struct cl_errorvector errv = new_cl_errorvector(&param1);
	uint8_t * syndrome = malloc(blkbytes);
	uint8_t * found_err = malloc(param1.N0 * blkbytes);
	uint8_t decoder_params[] = {5, 23, 23, 23, 23, 23};

	const int key_cycle_len = 50;
	const int n_key_cycles = 10;

	int fails = 0;

	fprintf(stderr, "t = %3i:   0%c", param1.t, '%');
	for (int key = 0; key < n_key_cycles; ++key) {
		cl_keygen(&param1, &sk, &pk, 0);
		for (j = 0; j < key_cycle_len; ++j) {
			cl_rand_block(msg1, blkbytes, 0);
			cl_rand_block(msg2, blkbytes, 0);
			cl_encode(msgs, &pk, codeword);
			cl_rand_errv(&errv);
			cl_inflict_errv(codeword, &errv);
			for (i = 0; i < blkbytes; ++i)
				syndrome[i] = 0;
			cl_calc_syndrome(codeword, &sk, syndrome);
			cl_retval status = cl_decoder_BF_fpt(syndrome, &sk, found_err, decoder_params);
			if (status == CL_DECODING_FAILURE) {
				++fails;
			}
		}
		fprintf(stderr, "\b\b\b\b%3i%c", (key + 1) * 100 / n_key_cycles, '%');
	}

	printf("%i, %i, %i, %i, %i, %i\n", param1.M, param1.N0, param1.w0, param1.t, key_cycle_len * n_key_cycles, fails);
	fprintf(stderr, "\b\b\b\b%i fail / %i total\n", fails, key_cycle_len * n_key_cycles);

	return 0;
}
