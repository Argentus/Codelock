/* = CODELOCK =
 * lightweight MDPC code-based cryptography library
 * ver. 0.1.0-prerelease
 *
 * file: codelock.h
 *
 */

#include <stdint.h>

struct cl_crypto_params {
	uint_fast16_t M;	// Circulant block size in bits
	uint_fast8_t N0;	// Number of circulant blocks in codeword
	uint_fast8_t w0;	// Parity-check matrix circulant block weight
	uint_fast8_t t;		// Weight of error vector
}

struct cl_pcm_key {
	struct cl_crypto_params * params;
	uint_fast16_t * key;
}

struct cl_gm_key {
	struct cl_crypto_params * params;
	unsigned int prepend_identity : 1;
	uint8_t * key;
}

struct cl_errorvector {
	struct cl_crypto_params * params;
	uint_fast16_t * errors;
}

enum {
       OK,
       FAILED
} cl_retval;

/*
 * 1. BASE MDPC FUNCTIONS
 */

// 
// 1.1 Key generation functions
//
cl_retval cl_calc_gm(struct cl_pcm_key * priv, struct cl_gm_key * pub);
cl_retval cl_calc_gm_with_identity(struct cl_pcm_key * priv, struct cl_gm_key * pub);
//
// 1.2 Encoding functions
//
cl_retval cl_encode_block(uint8_t * in, uint8_t * gm_block, uint_fast16_t blklen, uint8_t * out);
cl_retval cl_encode(uint8_t * in, struct cl_gm_key * gen, uint8_t * out);
cl_retval cl_inflict_errv(uint8_t* msg, );

//
// 1.1 Decoding functions
//
// 1.1.1 Common decoding functions
//
cl_retval cl_calc_syndrome(uint8_t * codeword, struct cl_pcm_key * key, uint8_t * syndrome);
cl_retval cl_count_upc(uint8_t * syndrome, struct cl_pcm_key * key, uint_fast16_t index);
// 1.1.1 Decoding algorithms
//
cl_retval cl_decode_BF1(uint8_t * syndrome, struct cl_pcm_key * key, uint8_t * out);
