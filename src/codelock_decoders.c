#include "codelock.h"

// Bit flipping algorithm with fixed preset thresholds
cl_retval cl_decoder_BF_fpt(uint8_t * syndrome, struct cl_pc_key * key, uint8_t * out_errv, void * params) {

	// Decoding params
	const uint8_t max_rounds = ((uint8_t*)params)[0];
	const uint8_t * flip_thresh = ((uint8_t*)params) + 1;

	// Useful helper consts
	const uint16_t blkbytes = (key->params->M / 8) + ((key->params->M % 8) ? 1 : 0);
	const uint32_t N = key->params->M * key->params->N0;
	const uint16_t Nbytes = blkbytes * key->params->N0;
	const uint16_t W = key->params->w0 * key->params->N0;

	uint8_t round, i;
	uint32_t j, k;

	for (j = 0; j < Nbytes; ++j)
		out_errv[j] = 0x0;

	uint8_t syndromeIsZero;
	uint32_t rotated_index;

	for (round = 0; round < max_rounds; ++round) {

		// Check if syndrome is zero, in that case message is decoded.
		syndromeIsZero = 1;
		for (j = 0; j < blkbytes; ++j)
			if (syndrome[j] != 0x00) {
				syndromeIsZero = 0;
				break;
			}
		if (syndromeIsZero) {
			break;
		}
		
		// Repeat for every subblock of message
		for (i = 0; i < key->params->N0; ++i) {
			// For every bit of subblock
			for (j = 0; j < key->params->M; ++j) {
				uint16_t n_upc = cl_count_upc(syndrome, key, (i * key->params->M) + j);
				if (n_upc >= flip_thresh[round]) {
					out_errv[(i * blkbytes) + (j / 8)] ^= 1 << (j % 8);

					// Update syndrome by adding corresponding line of secret key
					for (k = 0; k < W; ++k) {
						if ((key->key[k] >= i * key->params->M) && (key->key[k] < (i + 1) * key->params->M)) {
							rotated_index = ((N - key->key[k] + j ) % key->params->M);
							syndrome[(rotated_index)/8] ^= (1<<((rotated_index)%8));
						}
					}

					// Check if syndrome is zero, in that case message is decoded.
					syndromeIsZero=1;
					for (k=0;k<(key->params->M);k++)
						if (syndrome[k]!=0x00) {
							syndromeIsZero=0;
							break;
						}
					if (syndromeIsZero) {
						break;
					}
				}
			}
		}
	}

	if (!syndromeIsZero) {
		return CL_DECODING_FAILURE;	
	}

	return CL_OK;
}

// Bit flipping algorithm with flip threshold = max - delta
cl_retval cl_decoder_BF_dmt(uint8_t * syndrome, struct cl_pc_key * key, uint8_t * out_errv, void * params) {

	// Decoding params
	const uint8_t max_rounds = ((uint8_t*)params)[0];
	const uint8_t * thresh_delta = ((uint8_t*)params) + 1;

	// Useful helper consts
	const uint16_t blkbytes = (key->params->M / 8) + ((key->params->M % 8) ? 1 : 0);
	const uint32_t N = key->params->M * key->params->N0;
	const uint16_t Nbytes = blkbytes * key->params->N0;
	const uint16_t W = key->params->w0 * key->params->N0;

	uint8_t round, i;
	uint32_t j, k;
	uint16_t * upcs = malloc(N * sizeof(uint16_t));
	uint16_t threshold;

	for (j = 0; j < Nbytes; ++j)
		out_errv[j] = 0x0;

	uint8_t syndromeIsZero;
	uint32_t rotated_index;

	for (round = 0; round < max_rounds; ++round) {

		// Check if syndrome is zero, in that case message is decoded.
		syndromeIsZero = 1;
		for (j = 0; j < blkbytes; ++j)
			if (syndrome[j] != 0x00) {
				syndromeIsZero = 0;
				break;
			}
		if (syndromeIsZero) {
			break;
		}
		
		// Compute UPCs
		for (i = 0; i < key->params->N0; ++i) {
			for (j = 0; j < key->params->M; ++j) {
				upcs[i * key->params->M + j] = cl_count_upc(syndrome, key, (i * key->params->M) + j);
				if (upcs[i * key->params->M + j] > threshold || i + j == 0)
					threshold = upcs[i * key->params->M + j];
			}
		}

		threshold = threshold > thresh_delta[round] ? threshold - thresh_delta[round] : 1;

		// Flip all above threshold
		for (i = 0; i < key->params->N0; ++i) {
			for (j = 0; j < key->params->M; ++j) {
				if (upcs[i * key->params->M + j] >= threshold) {
					out_errv[(i * blkbytes) + (j / 8)] ^= 1 << (j % 8);

					// Update syndrome by adding corresponding line of secret key
					for (k = 0; k < W; ++k) {
						if ((key->key[k] >= i * key->params->M) && (key->key[k] < (i + 1) * key->params->M)) {
							rotated_index = ((N - key->key[k] + j ) % key->params->M);
							syndrome[(rotated_index)/8] ^= (1<<((rotated_index)%8));
						}
					}

					// Check if syndrome is zero, in that case message is decoded.
					syndromeIsZero=1;
					for (k=0;k<(key->params->M);k++)
						if (syndrome[k]!=0x00) {
							syndromeIsZero=0;
							break;
						}
					if (syndromeIsZero) {
						break;
					}
				}
			}
		}
	}

	free(upcs);

	if (!syndromeIsZero) {
		return CL_DECODING_FAILURE;	
	}

	return CL_OK;
}
