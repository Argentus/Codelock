#include "codelock.h"

cl_retval cl_encode_block(uint8_t * in, uint8_t * gm_block, uint16_t blklen, uint8_t * out) {

	// Useful helper consts
	const uint16_t blkbytes = (blklen / 8) + ((blklen % 8) ? 1 : 0);
	const uint8_t odd_bits = blklen % 8;
	const uint8_t padding_bits = (8 - odd_bits) % 8;

	uint32_t i, j;

	for (i = 0; i < blklen; i++) {

		if ( in[(i / 8)] & (1 << (i % 8)) )
			for (j = 0; j < blkbytes; ++j) {
				out[j] ^= gm_block[j];
			}

		// 1 bit rotation of GM block
		uint8_t tmp1 = gm_block[blkbytes - 1] >> (odd_bits + 7)%8;
		uint8_t tmp2;
		for (j = 0; j < blkbytes; ++j) {		
			tmp1 |= gm_block[j]<<1;
			tmp2 = gm_block[j]>>7;
			gm_block[j] = tmp1;
			tmp1 = tmp2;
		}
		gm_block[blkbytes - 1] &= 0xFF >> padding_bits;
	}

	return CL_OK;
}


cl_retval cl_encode(uint8_t ** in, struct cl_gen_key * gen, uint8_t * out) {

	uint8_t i;
	uint32_t j;

	// Useful helper consts
	const uint16_t blkbytes = (gen->params->M / 8) + ((gen->params->M % 8) ? 1 : 0);
	const uint8_t odd_bits = gen->params->M % 8;
	const uint8_t padding_bits = (8 - odd_bits) % 8;

	if (gen->prepend_identity == 1) {
		// Zero last block
		for (j = 0; j < blkbytes; ++j)
			out[(gen->params->N0 - 1) * blkbytes + j] = 0x00;
		for (i = 0; i < gen->params->N0 - 1; ++i) {
			// Copy message
			for (j = 0; j < blkbytes; ++j)
				out[i * blkbytes + j] = in[i][j];
			out[(i + 1) * blkbytes - 1] &= 0xFF >> padding_bits;
			// Compute parity
			cl_retval err =  cl_encode_block(in[i], gen->key + i * blkbytes, gen->params->M, out + ((gen->params->N0 - 1) *blkbytes));
			if (err != CL_OK)
				return err;
		}
	} else {
		// Key without identity (BIKE-1 style)
		for (i = 0; i < gen->params->N0 - 1; ++i) {
			for (j = 0; j < blkbytes; ++j)
				out[i * blkbytes + j] = 0x00;
			cl_retval err = cl_encode_block(in[i], gen->key, gen->params->M, out + i * blkbytes);
			if (err != CL_OK)
				return err;
		}
		for (j = 0; j < blkbytes; ++j)
			out[(gen->params->N0 - 1) * blkbytes + j] = 0x00;
		for (i = 0; i < gen->params->N0 - 1; ++i) {
			cl_retval err = cl_encode_block(in[i], gen->key + (i + 1) * blkbytes, gen->params->M, out + (gen->params->N0 - 1) * blkbytes);
			if (err != CL_OK)
				return err;
		}
	}

	return CL_OK;
}

cl_retval cl_calc_syndrome(uint8_t * codeword, struct cl_pc_key * key, uint8_t * syndrome) {
	
	uint8_t i;
	uint32_t j, k, rotated_index;

	// Useful helper consts
	const uint16_t blkbytes = (key->params->M / 8) + ((key->params->M % 8) ? 1 : 0);
	const uint32_t N = key->params->M * key->params->N0;

	// Init syndrome to 0
	for (j = 0; j < blkbytes; ++j)
		syndrome[j] = 0x00;

	for (i = 0; i < key->params->N0; ++i) {
		for (j = 0; j < key->params->M; ++j) {
			// If this bit is set in code
			if ( (codeword[(i * blkbytes) + (j / 8)] & (1 << (j % 8))) ) {
				// Every set bit of private key
				for (k = i * key->params->w0; k < (i + 1) * key->params->w0; ++k) {
					// Rotate it to get correct position in circulant matrix
					rotated_index = (uint32_t)((N - key->key[k] + j ) % key->params->M);
					// And add it to the syndrome.
					syndrome[(rotated_index)/8] ^= (1<<((rotated_index)%8));
				}
			}
		}
	}

	return CL_OK;
}


uint16_t cl_count_upc(uint8_t * syndrome, struct cl_pc_key * key, uint16_t index) {

	// Useful helper consts
	const uint16_t blkbytes = (key->params->M / 8) + ((key->params->M % 8) ? 1 : 0);
	const uint32_t N = key->params->M * key->params->N0;

	uint8_t block = index / key->params->M;
	index = index % key->params->M;

	uint32_t k;
	uint32_t n_upc = 0;
	uint32_t rotated_index;

	for (k = block * key->params->w0; k <  (block + 1) * key->params->w0; ++k) {
		rotated_index = ((N - key->key[k] + index ) % key->params->M);
		if ( (syndrome[(rotated_index / 8)] & (1 << (rotated_index % 8))) )
			n_upc++;
	}

	return n_upc;
}

void cl_sort_errv(struct cl_errorvector * errv) {
	uint16_t n = errv->params->t;
	uint32_t i;
	do {
		uint16_t newn = 0;
		for (i = 1; i < n; ++i) {
			if (errv->errors[i - 1] > errv->errors[i]) {
				uint32_t tmp = errv->errors[i];
				errv->errors[i] = errv->errors[i - 1];
				errv->errors[i - 1] = tmp;
				newn = i;
			}
		}
		n = newn;
	} while (n != 0);
}

cl_retval cl_inflict_errv(uint8_t* msg, struct cl_errorvector * errv) {

	// Useful helper consts
	const uint16_t blkbytes = (errv->params->M / 8) + ((errv->params->M % 8) ? 1 : 0);

	uint32_t i;
	for (i = 0; i < errv->params->t; ++i) {
		uint8_t block = errv->errors[i] / errv->params->M;
		uint32_t subindex = errv->errors[i] % errv->params->M;
		msg[(block * blkbytes) + (subindex / 8)] ^= (1 << (subindex % 8));
	}
	return CL_OK;
}

struct cl_pc_key new_cl_pc_key(struct cl_crypto_params * params) {
	struct cl_pc_key result;
	result.params = params;
	result.key = malloc(params->w0 * params->N0 * sizeof(uint32_t));
	return result;
}

struct cl_gen_key new_cl_gen_key(struct cl_crypto_params * params) {
	struct cl_gen_key result;
	result.params = params;
	result.key = malloc(params->N0 * ((params->M / 8) + ((params->M % 8) ? 1 : 0)) * sizeof(uint8_t));
	return result;
}

struct cl_errorvector new_cl_errorvector(struct cl_crypto_params * params) {
	struct cl_errorvector result;
	result.params = params;
	result.errors = malloc(params->t * sizeof(uint32_t));
	return result;
}
