AR = /usr/bin/ar
CC = /usr/bin/gcc
CFLAGS = -Wall -O3

test: test.c adr.c endian.c keygen.c private_key_gen.c    \
      build_merkle.c sphincs_hash.c hmac.c hmac_drbg.c lms_compute.c \
      lm_ots_common.c lm_ots_sign.c load.c param.c sha256.c \
      sign.c step.c verify.c wots.c zeroize.c tune.h
	$(CC) $(CFLAGS) -o test test.c adr.c endian.c keygen.c \
		private_key_gen.c build_merkle.c sphincs_hash.c hmac.c \
                hmac_drbg.c lms_compute.c lm_ots_common.c \
                lm_ots_sign.c load.c param.c sha256.c sign.c \
                step.c verify.c wots.c zeroize.c -lcrypto
