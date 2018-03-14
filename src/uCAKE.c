#include "uCAKE.h"

char system_initialized = 0;

uCAKE_STATUS uCAKE_MDPC_encode_subblock(const uCAKE_subblock msg, uCAKE_subblock key, uCAKE_subblock code) {
	
	uCAKE_STATUS return_status = uCAKE_SUCCESS;
	uint32_t i, j;

	for (i = 0; i < uCAKE_MDPC_M_BYTES; ++i)
		code[i] = 0;

	/* 
	 * Encode - multiply message by generator matrix
	 */	
	if (msg[0] & ((uint8_t) 1))
		for (j = 0; j < uCAKE_MDPC_M_BYTES; ++j) {
			code[j] = key[j];
		}
	
	for (i = 1; i < uCAKE_MDPC_M; i++) {

		// 1 bit rotation of key subblock
		uint8_t buff = key[uCAKE_MDPC_M_BYTES - 1];
		uint8_t buff2;
		for (j = 0; j < uCAKE_MDPC_M_BYTES - 1; ++j) {		
			buff |= key[j]<<1;
			buff2 = key[j]>>7;
			key[j] = buff;
			buff = buff2;
		}	
		key[uCAKE_MDPC_M_BYTES - 1] = buff;

		if ( msg[(i / 8)] & (1 << (i % 8)) )
			for (j = 0; j < uCAKE_MDPC_M_BYTES; ++j) {
				code[j] ^= key[j];
			}
	}
	
	// Rotation of key subblock back to original
	uint8_t buff = key[uCAKE_MDPC_M_BYTES - 1];
	uint8_t buff2;
	for (j = 0; j < uCAKE_MDPC_M_BYTES - 1; ++j) {		
		buff |= key[j]<<1;
		buff2 = key[j]>>7;
		key[j] = buff;
		buff = buff2;
	}	
	key[uCAKE_MDPC_M_BYTES - 1] = buff;

	return return_status;
}

uCAKE_STATUS uCAKE_MDPC_encode_msg(uCAKE_subblock msg, uCAKE_public_key pk, uCAKE_codeword result) {

	int i, j;

	for (i = 0; i < uCAKE_MDPC_N0; ++i) {
		uCAKE_subblock code;
		uCAKE_STATUS ret = uCAKE_MDPC_encode_subblock(	msg,
								pk + (i * uCAKE_MDPC_M_BYTES),
								code );
		if (ret != uCAKE_SUCCESS)
			return ret;

		for (j = 0; j < uCAKE_MDPC_M_BYTES; ++j) {
			result[(i * uCAKE_MDPC_M_BYTES) + j] = code[j];
		}
	}

	return uCAKE_SUCCESS;
}

#ifdef uCAKE_USE_SHORT_PUBLIC_KEYS
uCAKE_STATUS uCAKE_MDPC_encode_msg_sk(uCAKE_subblock msg, uCAKE_public_key_short pk, uCAKE_codeword result) {

	int i,j;

	for (i = 0; i < uCAKE_MDPC_M_BYTES; ++i)
		result[i] = msg[i];

	uCAKE_subblock code;
	uCAKE_STATUS ret = uCAKE_MDPC_encode_subblock(	msg,
							pk,
							code );
	if (ret != uCAKE_SUCCESS)
		return ret;

	for (j = 0; j < uCAKE_MDPC_M_BYTES; ++j) {
		result[uCAKE_MDPC_M_BYTES + j] = code[j];
	}

	return uCAKE_SUCCESS;
}
#endif

uCAKE_STATUS uCAKE_inflict_errv(uCAKE_codeword code, uCAKE_errv errv) {
	int i;
	for (i = 0; i < uCAKE_MDPC_T; ++i) {
		int subblock = errv[i] / uCAKE_MDPC_M;
		int subindex = errv[i] % uCAKE_MDPC_M;
		code[(subblock * uCAKE_MDPC_M_BYTES) + (subindex / 8)] ^= (1 << (subindex % 8));
	}
	return uCAKE_SUCCESS;
}

uCAKE_STATUS uCAKE_MDPC_decode_bf1(uCAKE_codeword code, uCAKE_secret_key sk, char zero_message) {

	uCAKE_STATUS return_status;
	uint16_t round, i, j, k;
	const uint8_t max_rounds = 13;
	const uint8_t flip_thresh[] = {43, 42, 41, 40, 39, 45, 44, 43, 42, 47, 46, 45, 43, 43};

	uCAKE_subblock syndrome;
	return_status = uCAKE_calc_syndrome(code, sk, syndrome);

	if (return_status != uCAKE_SUCCESS)
		return return_status;

	// If desired, set msg to 0 to find error vector
	if (zero_message) {
		for (i = 0; i < uCAKE_MDPC_N_BYTES; ++i)
			code[i] = 0x0;
	}

	uint8_t syndromeIsZero;
	uint32_t rotated_index;

	for (round = 0; round < max_rounds; ++round) {

		// Check if syndrome is zero, in that case message is decoded.
		syndromeIsZero = 1;
		for (j = 0; j < (uCAKE_MDPC_M_BYTES); ++j)
			if (syndrome[j] != 0x00) {
				syndromeIsZero = 0;
				break;
			}
		if (syndromeIsZero)
			break;
		
		// Repeat for every subblock of message
		for (i = 0; i < uCAKE_MDPC_N0; ++i) {
			// For every bit of subblock
			for (j = 0; j < uCAKE_MDPC_M; ++j) {
				uint16_t n_upc = uCAKE_MDPC_count_upc(sk, syndrome, (i * uCAKE_MDPC_M) + j);
				if (n_upc >= flip_thresh[round]) {
					code[(i * uCAKE_MDPC_M_BYTES) + (j / 8)] ^= 1 << (j % 8);

					// Update syndrome by adding corresponding line of secret key
					for (k = 0; k < uCAKE_MDPC_W; ++k) {
						if ((sk[k] >= i * uCAKE_MDPC_M) && (sk[k] < (i + 1) * uCAKE_MDPC_M)) {
							rotated_index = ((uCAKE_MDPC_N - sk[k] + j ) % uCAKE_MDPC_M);
							syndrome[(rotated_index)/8] ^= (1<<((rotated_index)%8));
						}
					}

					// Check if syndrome is zero, in that case message is decoded.
					syndromeIsZero=1;
					for (k=0;k<(uCAKE_MDPC_M_BYTES);k++)
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
		return uCAKE_DECODING_FAILURE;	
	}

	return uCAKE_SUCCESS;
}

uCAKE_STATUS uCAKE_calc_syndrome(uCAKE_codeword code, uCAKE_secret_key sk, uCAKE_subblock syndrome) {

	uint16_t i, j, k;
	uint32_t rotated_index;

	// Init syndrome to 0
	for (i = 0; i < uCAKE_MDPC_M_BYTES; ++i)
		syndrome[i] = 0x0;

	// For every message subblock
	for (i = 0; i < uCAKE_MDPC_N0; ++i) {
		// For every bit of the subblock
		for (j = 0; j < uCAKE_MDPC_M; ++j) {			// first half (message part)
			// If this bit is set in code
			if ( (code[(i * uCAKE_MDPC_M_BYTES) + (j / 8)] & (1 << (j % 8))) ) {
				// Every set bit of private key
				for (k = 0; k < uCAKE_MDPC_W; ++k) {
					// If this bit falls into current (circulant) subblock
					if ((sk[k] >= i * uCAKE_MDPC_M) && (sk[k] < (i + 1) * uCAKE_MDPC_M)) {
						// Rotate it to get correct position in circulant matrix
						rotated_index = ((uCAKE_MDPC_N - sk[k] + j ) % uCAKE_MDPC_M);
						// And add it to the syndrome.
						syndrome[(rotated_index)/8] ^= (1<<((rotated_index)%8));	
					}
				}
			}
		}
	}

	return uCAKE_SUCCESS;
}

uint16_t uCAKE_MDPC_count_upc(uCAKE_secret_key sk, uCAKE_subblock syndrome, uint16_t index) {

	uint8_t subblock = index / uCAKE_MDPC_M;
	index = index % uCAKE_MDPC_M;

	uint16_t k;
	uint16_t n_upc = 0;
	uint32_t rotated_index;

	for (k = 0; k < uCAKE_MDPC_W; ++k) {
		// If this bit falls into current (circulant) subblock
		if ((sk[k] >= subblock * uCAKE_MDPC_M) && (sk[k] < (subblock + 1) * uCAKE_MDPC_M)) {
			// Rotate it to get correct position in circulant matrix
			rotated_index = ((uCAKE_MDPC_N - sk[k] + index ) % uCAKE_MDPC_M);
			if ( (syndrome[(rotated_index / 8)] & (1 << (rotated_index % 8))) )
				n_upc++;	
		}
	}

	return n_upc;
}

uCAKE_STATUS uCAKE_rand_errv(uCAKE_errv errv) {
	
	int i;
	for (i = 0; i < uCAKE_MDPC_T; ++i) {
		char success = 0;
		while (!success) {
			success = 1;
			errv[i] = uCAKE_get_random(0, uCAKE_MDPC_N - 1);
			int j;
			for (j = 0; j < i; ++j) {
				if (errv[i] == errv[j]) {
					success = 0;
					break;
				}
			}
		}
	}

	uCAKE_sort_errv(errv, -1, -1);
	return uCAKE_SUCCESS;
}

uCAKE_STATUS uCAKE_rand_secret_key(uCAKE_secret_key sk) {
	
	int i;
	for (i = 0; i < uCAKE_MDPC_W0; ++i) {
		char success = 0;
		while (!success) {
			sk[i] = uCAKE_get_random(0, uCAKE_MDPC_M - 1);
			int j;
			for (j = 0; j < i; ++j) {
				if (sk[i] == sk[j])
					break;
			}
			success = 1;
		}
	}
	for (i = 0; i < uCAKE_MDPC_W0; ++i) {
		char success = 0;
		while (!success) {
			sk[i + uCAKE_MDPC_W0] = uCAKE_get_random(0, uCAKE_MDPC_M - 1) + uCAKE_MDPC_M;
			int j;
			for (j = 0; j < i; ++j) {
				if (sk[i + uCAKE_MDPC_W0] == sk[j + uCAKE_MDPC_W0])
					break;
			}
			success = 1;
		}
	}
	return uCAKE_SUCCESS;
}

uCAKE_STATUS uCAKE_calc_public_key(uCAKE_secret_key sk, uCAKE_subblock g, uCAKE_public_key pk) {

	uint16_t i, j, k;
	uint32_t rotated_index;
	// Init public key to 0
	for (i = 0; i < uCAKE_MDPC_N_BYTES; ++i)
		pk[i] = 0x0;

	// g0 = g . h_1^T
	for (j = 0; j < uCAKE_MDPC_M; ++j) {
		// If this bit is set in g
		if ( (g[(j / 8)] & (1 << (j % 8))) ) {
			// Every set bit of private key in relevant subblock
			for (k = uCAKE_MDPC_W0; k < uCAKE_MDPC_W; ++k) {
				// Rotate it to get correct position in circulant matrix		
				rotated_index = (((uCAKE_MDPC_N) - sk[k] + j ) % uCAKE_MDPC_M);
				// And add it to the public key.		
				pk[(rotated_index)/8] ^= (1<<((rotated_index)%8));
			}
		}
	}

	// g1 = g . h_0^T
	for (j = 0; j < uCAKE_MDPC_M; ++j) {
		// If this bit is set in g
		if ( (g[(j / 8)] & (1 << (j % 8))) ) {
			// Every set bit of private key in relevant subblock
			for (k = 0; k < uCAKE_MDPC_W0; ++k) {
				// Rotate it to get correct position in circulant matrix
				rotated_index = ((uCAKE_MDPC_N - sk[k] + j ) % uCAKE_MDPC_M);
				// And add it to the public key.
				pk[uCAKE_MDPC_M_BYTES + (rotated_index)/8] ^= (1<<((rotated_index)%8));
			}
		}
	}


	return uCAKE_SUCCESS;
}


uCAKE_STATUS uCAKE_keygen(uCAKE_secret_key sk, uCAKE_public_key pk) {
	uCAKE_STATUS status;

	if ((status = uCAKE_rand_secret_key(sk)) != uCAKE_SUCCESS)
		return status;

	uCAKE_subblock g;
	if ((status = uCAKE_rand_subblock(g)) != uCAKE_SUCCESS)
		return status;
	// g must have odd weight
	int i;
	uint8_t parity = 0;
	for (i = 0; i < uCAKE_MDPC_M_BYTES - 1; ++i) {
		parity ^= g[i];
	}
	uint8_t odd;	
	do {
	odd = parity ^ g[uCAKE_MDPC_M_BYTES - 1];
	odd ^= odd >> 4;
	odd ^= odd >> 2;
	odd ^= odd >> 1;
	odd &= 0x1;

	if (!odd)
		g[uCAKE_MDPC_M_BYTES - 1] = uCAKE_rand8();

	} while (!odd);

	if ((status = uCAKE_calc_public_key(sk, g, pk)) != uCAKE_SUCCESS)
		return status;
	
	return uCAKE_SUCCESS;
}

void uCAKE_sort_errv(uCAKE_errv errv, int first, int last) {
	int n = uCAKE_MDPC_T;
	int i;
	do {
		int newn = 0;
		for (i = 1; i < n; ++i) {
			if (errv[i - 1] > errv[i]) {
				uint16_t tmp = errv[i];
				errv[i] = errv[i - 1];
				errv[i - 1] = tmp;
				newn = i;
			}
		}
		n = newn;
	} while (n != 0);
}
