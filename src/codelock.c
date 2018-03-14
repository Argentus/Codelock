#include "codelock.h"

cl_retval cl_encode_block(uint8_t * in, uint8_t * gm_block, uint_fast16_t blklen, uint8_t * out) {
	
	cl_retval return_status = OK;

	// Useful helper consts
	const uint_fast16_t blkbytes = (blklen / 8) + (blklen % 8) ? 1 : 0;
	const uint_fast8_t odd_bits = blklen % 8;
	const uint_fast8_t padding_bits = (8 - odd_bits) % 8;

	uint_fast16_t i, j;

	// Multiply by generator matrix	
	if (in[0] & ((uint8_t) 1))
		for (i = 0; i < blkbytes; ++i)
			code[j] = gm_block[j];
	else
		for (i = 0; i < blkbytes; ++i)
			out[i] = 0;
	
	for (i = 1; i < uCAKE_MDPC_M; i++) {

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

		if ( in[(i / 8)] & (1 << (i % 8)) )
			for (j = 0; j < blkbytes; ++j) {
				out[j] ^= gm_block[j];
			}
	}
	
	// Rotation of GM block back to original
	uint8_t tmp1 = gm_block[blkbytes - 1] >> (odd_bits + 7)%8;
	uint8_t tmp2;
	for (j = 0; j < blkbytes; ++j) {		
		tmp1 |= gm_block[j]<<1;
		tmp2 = gm_block[j]>>7;
		gm_block[j] = tmp1;
		tmp1 = tmp2;
	}
	gm_block[blkbytes - 1] &= 0xFF >> padding_bits;

	return return_status;
}
