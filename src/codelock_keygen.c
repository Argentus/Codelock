#include "codelock.h"

cl_retval cl_calc_public_key(struct cl_pc_key * sk, struct cl_gen_key * pk, char prepend_identity, uint8_t * g) {

	pk->params = sk->params;
	pk->prepend_identity = prepend_identity != 0 ? 1 : 0;

	// Useful helper consts
	const uint16_t blkbytes = (sk->params->M / 8) + ((sk->params->M % 8) ? 1 : 0);
	const uint32_t N = sk->params->M * sk->params->N0;
	const uint16_t Nbytes = blkbytes * sk->params->N0;

	if (prepend_identity != 0) {
		// Key generation using inversion not implemented yet
		return CL_NOT_IMPLEMENTED;
	} else {
		// BIKE-1 style key : no identity
		uint8_t i;
		uint32_t j, k, rotated_index;

		// Init public key to 0
		for (j = 0; j < Nbytes; ++j) {
			pk->key[j] = 0x0;
		}

		for (i = 0; i < sk->params->N0; ++i) {
			uint8_t blk = (sk->params->N0 + i - 1) % sk->params->N0;
			for (j = 0; j < sk->params->M; ++j) {
				// If this bit is set in g
				if ( (g[(j / 8)] & (1 << (j % 8))) ) {
					// Every set bit of private key in relevant subblock
					for (k = blk * sk->params->w0; k < (blk + 1) * sk->params->w0; ++k) {
						// Rotate it to get correct position in circulant matrix		
						rotated_index = ((N - sk->key[k] + j ) % sk->params->M);
						// And add it to the public key.		
						pk->key[i * blkbytes + (rotated_index)/8] ^= (1<<((rotated_index)%8));
					}
				}
			}
		}
	}

	return CL_OK;
}

cl_retval cl_keygen(struct cl_crypto_params * params, struct cl_pc_key * sk, struct cl_gen_key * pk, char prepend_identity) {

	// Useful helper consts
	const uint16_t blkbytes = (params->M / 8) + ((params->M % 8) ? 1 : 0);

	cl_retval status;

	sk->params = params;
	if ((status = cl_rand_pc_key(sk)) != CL_OK)
		return status;

	if (prepend_identity != 0) {
		// Generation of keys using inversion is not yet supported
		return CL_NOT_IMPLEMENTED;
	} else {
		// BIKE-1 style keys : No identity
		uint8_t * g = malloc(blkbytes * sizeof(uint8_t));
		if ((status = cl_rand_block(g, blkbytes, 1)) != CL_OK)
			return status;
		if ((status = cl_calc_public_key(sk, pk, 0, g)) != CL_OK)
			return status;
	}
	
	return CL_OK;
}
