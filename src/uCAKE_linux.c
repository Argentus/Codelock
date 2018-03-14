#include "uCAKE.h"

#include <fcntl.h>
#include <unistd.h>

#define RAND_FILE_PATH "/dev/urandom"

int random_fd = -1;


uCAKE_STATUS uCAKE_init_system() {

	random_fd = open(RAND_FILE_PATH, O_RDONLY);
	if (random_fd < 0) {
		random_fd = -1;
		return uCAKE_SYSTEM_ERROR;
	}

	system_initialized = 1;
	return uCAKE_SUCCESS;
}

uint16_t uCAKE_get_random(uint16_t from, uint16_t to) {

	uint16_t result;
	char success = 0;

	while (!success) {
		read(random_fd, &result, 2);
		if (result >= from && result <= to)
			success = 1;
	}

	return result;
}

uint8_t uCAKE_rand8() {
	uint8_t result;
	read(random_fd, &result, 1);
	return result;
}

uCAKE_STATUS uCAKE_rand_subblock(uCAKE_subblock result) {
	if (read(random_fd, result, uCAKE_MDPC_M_BYTES) != uCAKE_MDPC_M_BYTES)
		return uCAKE_SYSTEM_ERROR;
	return uCAKE_SUCCESS;
}
