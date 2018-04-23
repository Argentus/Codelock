/* = CODELOCK =
 * lightweight MDPC code-based cryptography library
 * ver. 0.1.0-prerelease
 *
 * file: codelock.h
 *
 */

#include <stdint.h>
#include <stdlib.h>

struct cl_crypto_params {
	uint32_t M;	// Circulant block size in bits
	uint8_t N0;	// Number of blocks
	uint16_t w0;	// Parity-check matrix circulant block weight
	uint16_t t;	// Weight of error vector
};

struct cl_pc_key {
	struct cl_crypto_params * params;
	uint32_t * key;
};

struct cl_gen_key {
	struct cl_crypto_params * params;
	unsigned int prepend_identity : 1;
	uint8_t * key;
};

struct cl_errorvector {
	struct cl_crypto_params * params;
	uint32_t * errors;
};

typedef enum {
	CL_OK = 0,
	CL_FAILED,
	CL_NOT_IMPLEMENTED,
	CL_DECODING_FAILURE,
	CL_RAND_NOT_INIT,
	CL_SYSTEM_ERROR
} cl_retval;

extern uint8_t rand_initialized;

/*
 * 1. BASE QC-MDPC FUNCTIONS
 */

// 
// 1.1 Key generation functions
//
cl_retval cl_calc_public_key(struct cl_pc_key * sk, struct cl_gen_key * pk, char prepend_identity, uint8_t * g);
cl_retval cl_keygen(struct cl_crypto_params * params, struct cl_pc_key * sk, struct cl_gen_key * pk, char prepend_identity);
//
// 1.2 Encoding functions
//
cl_retval cl_encode_block(uint8_t * in, uint8_t * gm_block, uint16_t blklen, uint8_t * out);
cl_retval cl_encode(uint8_t ** in, struct cl_gen_key * gen, uint8_t * out);
//
// 1.3 Decoding functions
//
// 1.3.1 Common decoding functions
cl_retval cl_calc_syndrome(uint8_t * codeword, struct cl_pc_key * key, uint8_t * syndrome);
uint16_t cl_count_upc(uint8_t * syndrome, struct cl_pc_key * key, uint16_t index);
//
// 1.3.1 Decoding algorithms
cl_retval cl_decoder_BF_fpt(uint8_t * syndrome, struct cl_pc_key * key, uint8_t * out_errv, void * params);
cl_retval cl_decoder_BF_dmt(uint8_t * syndrome, struct cl_pc_key * key, uint8_t * out_errv, void * params);
//
// 1.4 Helper functions
//
cl_retval cl_inflict_errv(uint8_t* msg, struct cl_errorvector * errv);
void cl_sort_errv(struct cl_errorvector * errv);
struct cl_pc_key new_cl_pc_key(struct cl_crypto_params * params);
struct cl_gen_key new_cl_gen_key(struct cl_crypto_params * params);
struct cl_errorvector new_cl_errorvector(struct cl_crypto_params * params);

/*
 * 2. RNG FUNCTIONS
 */
cl_retval cl_init_rand();
uint32_t cl_get_random(uint32_t from, uint32_t to);
uint8_t cl_rand8();
cl_retval cl_rand_block(uint8_t * result, uint16_t blkbytes, char force_odd);
cl_retval cl_rand_pc_key(struct cl_pc_key * key);
cl_retval cl_rand_errv(struct cl_errorvector * errv);

