#include <mbelib.h>

#include <stdio.h>
#include <stdint.h>
#include <math.h>

#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a,b) (((a) > (b)) ? (a) : (b))
#endif

typedef uint8_t flag_t;

static uint8_t rW[36] = {
  0, 1, 0, 1, 0, 1,
  0, 1, 0, 1, 0, 1,
  0, 1, 0, 1, 0, 1,
  0, 1, 0, 1, 0, 2,
  0, 2, 0, 2, 0, 2,
  0, 2, 0, 2, 0, 2
};

static uint8_t rX[36] = {
  23, 10, 22, 9, 21, 8,
  20, 7, 19, 6, 18, 5,
  17, 4, 16, 3, 15, 2,
  14, 1, 13, 0, 12, 10,
  11, 9, 10, 8, 9, 7,
  8, 6, 7, 5, 6, 4
};

static uint8_t rY[36] = {
  0, 2, 0, 2, 0, 2,
  0, 2, 0, 3, 0, 3,
  1, 3, 1, 3, 1, 3,
  1, 3, 1, 3, 1, 3,
  1, 3, 1, 3, 1, 3,
  1, 3, 1, 3, 1, 3
};

static uint8_t rZ[36] = {
  5, 3, 4, 2, 3, 1,
  2, 0, 1, 13, 0, 12,
  22, 11, 21, 10, 20, 9,
  19, 8, 18, 7, 17, 6,
  16, 5, 15, 4, 14, 3,
  13, 2, 12, 1, 11, 0
};

static void base_bytetobits(uint8_t byte, flag_t *bits) {
	bits[0] = (byte & 128 ? 1 : 0);
	bits[1] = (byte & 64 ? 1 : 0);
	bits[2] = (byte & 32 ? 1 : 0);
	bits[3] = (byte & 16 ? 1 : 0);
	bits[4] = (byte & 8 ? 1 : 0);
	bits[5] = (byte & 4 ? 1 : 0);
	bits[6] = (byte & 2 ? 1 : 0);
	bits[7] = (byte & 1 ? 1 : 0);
}

static void base_bytestobits(uint8_t *bytes, uint16_t bytes_length, flag_t *bits, uint16_t bits_length) {
	uint16_t i;

	for (i = 0; i < min(bits_length/8, bytes_length); i++)
		base_bytetobits(bytes[i], &bits[i*8]);
}

static void processagc(float *outbuf, float *aout_gain) {
	int i, n;
	float aout_abs, max, gainfactor, gaindelta, maxbuf;
	static aout_max_buf[33];
	static uint8_t aout_max_buf_idx;

	// Detect max. level
	max = 0;
	for (n = 0; n < 160; n++) {
		aout_abs = fabsf(outbuf[n]);
		if (aout_abs > max)
			max = aout_abs;
	}
	aout_max_buf[aout_max_buf_idx++] = max;
	if (aout_max_buf_idx > 24)
		aout_max_buf_idx = 0;

	// Lookup max. history
	for (i = 0; i < 25; i++) {
		maxbuf = aout_max_buf[i];
		if (maxbuf > max)
			max = maxbuf;
	}

	// Determine optimal gain level
	if (max > 0.0f)
		gainfactor = (32767.0f / max);
	else
		gainfactor = 50.0f;

	if (gainfactor < *aout_gain) {
		*aout_gain = gainfactor;
		gaindelta = 0.0f;
	} else {
		if (gainfactor > 50.0f)
			gainfactor = 50.0f;

		gaindelta = gainfactor - *aout_gain;
		if (gaindelta > (0.05f * (*aout_gain)))
			gaindelta = (0.05f * (*aout_gain));
	}

	// Adjust output gain
	*aout_gain += gaindelta;
}

int main(void) {
	FILE *fin, *fout;
	size_t bytesread;
	char ambe_fr[4][24];
	char ambe_d[49];
	uint8_t ambe_fr_bytes[9];
	uint8_t ambe_fr_bits[sizeof(ambe_fr_bytes)*8];
	int i, j;
	int errs, errs2;
	char err_str[64];
	mbe_parms cur_mp, prev_mp, prev_mp_enhanced;
	float outbuf[1000];
	int16_t outbuf_s[160];
	float gain = 25;
	uint8_t *w, *x, *y, *z;

	mbe_initMbeParms(&cur_mp, &prev_mp, &prev_mp_enhanced);

	fin = fopen("out.voice", "r");
	fout = fopen("out.raw", "w");
	while (!feof(fin)) {
		bytesread = fread(ambe_fr_bytes, 1, sizeof(ambe_fr_bytes), fin);
		printf("read %2u bytes: ", bytesread);
		for (i = 0; i < bytesread; i++)
			printf("%.2x", ambe_fr_bytes[i]);
		printf("\n");
		base_bytestobits(ambe_fr_bytes, sizeof(ambe_fr_bytes), ambe_fr_bits, sizeof(ambe_fr_bits));
		printf("               ");
		for (i = 0; i < sizeof(ambe_fr_bits); i++)
			printf("%u", ambe_fr_bits[i]);
		printf("\n");

		// Deinterleaving
		w = rW;
		x = rX;
		y = rY;
		z = rZ;
		for (i = 0; i < sizeof(ambe_fr_bytes); i++) {
			for (j = 0; j < 8; j+=2) {
				ambe_fr[*w][*x] = ambe_fr_bits[i*8+j];
				ambe_fr[*y][*z] = ambe_fr_bits[i*8+j+1];
				w++;
				x++;
				y++;
				z++;
			}
		}

		mbe_processAmbe3600x2450Framef(outbuf, &errs, &errs2, err_str, ambe_fr, ambe_d, &cur_mp, &prev_mp, &prev_mp_enhanced, 3);

		if (errs2 > 0)
			printf("decodeAmbe2450Parms: errs2: %u, err_str: %s\n", errs2, err_str);

		for (i = 0; i < 160; i++) {
			processagc(outbuf, &gain);
			outbuf[i] *= gain;
			if (outbuf[i] > 32767.0f)
				outbuf[i] = 32767.0f;
			else if (outbuf[i] < -32767.0f)
				outbuf[i] = -32767.0f;

			outbuf_s[i] = lrintf(outbuf[i]);
		}
		fwrite(outbuf_s, 2, 160, fout);
	}
	fclose(fin);
	fclose(fout);

	return 0;
}
