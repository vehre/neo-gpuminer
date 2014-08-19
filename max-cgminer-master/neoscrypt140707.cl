/* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20 */

#define rotl(x,y) rotate(x,y)
#define Ch(x,y,z) bitselect(z,y,x)
#define Maj(x,y,z) Ch((x^z),y,z)
#define ROTR32(a,b) (((a) >> (b)) | ((a) << (32 - b)))
#define ROTL32(a,b) rotate(a,b)

__constant uint ES[2] = { 0x00FF00FF, 0xFF00FF00 };
#define EndianSwap(n) (rotate(n & ES[0], 24U)|rotate(n & ES[1], 8U))

#define BLOCK_SIZE 64U

/* Salsa20, rounds must be a multiple of 2 */
void neoscrypt_salsa(uint *X, uint rounds) {
    uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, t;

    x0 = X[0];   x1 = X[1];   x2 = X[2];   x3 = X[3];
    x4 = X[4];   x5 = X[5];   x6 = X[6];   x7 = X[7];
    x8 = X[8];   x9 = X[9];  x10 = X[10]; x11 = X[11];
   x12 = X[12]; x13 = X[13]; x14 = X[14]; x15 = X[15];

#define quarter(a, b, c, d) \
    t = a + d; t = rotate(t,  7u); b ^= t; \
    t = b + a; t = rotate(t,  9u); c ^= t; \
    t = c + b; t = rotate(t, 13u); d ^= t; \
    t = d + c; t = rotate(t, 18u); a ^= t;

    for(; rounds; rounds -= 2) {
        quarter( x0,  x4,  x8, x12);
        quarter( x5,  x9, x13,  x1);
        quarter(x10, x14,  x2,  x6);
        quarter(x15,  x3,  x7, x11);
        quarter( x0,  x1,  x2,  x3);
        quarter( x5,  x6,  x7,  x4);
        quarter(x10, x11,  x8,  x9);
        quarter(x15, x12, x13, x14);
    }

    X[0] += x0;   X[1] += x1;   X[2] += x2;   X[3] += x3;
    X[4] += x4;   X[5] += x5;   X[6] += x6;   X[7] += x7;
    X[8] += x8;   X[9] += x9;  X[10] += x10; X[11] += x11;
   X[12] += x12; X[13] += x13; X[14] += x14; X[15] += x15;

#undef quarter
}

/* ChaCha20, rounds must be a multiple of 2 */
void neoscrypt_chacha(uint *X, uint rounds) {
    uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, t;

    x0 = X[0];   x1 = X[1];   x2 = X[2];   x3 = X[3];
    x4 = X[4];   x5 = X[5];   x6 = X[6];   x7 = X[7];
    x8 = X[8];   x9 = X[9];  x10 = X[10]; x11 = X[11];
   x12 = X[12]; x13 = X[13]; x14 = X[14]; x15 = X[15];

#define quarter(a,b,c,d) \
    a += b; t = d ^ a; d = ROTL32(t, 16u); \
    c += d; t = b ^ c; b = ROTL32(t, 12u); \
    a += b; t = d ^ a; d = ROTL32(t,  8u); \
    c += d; t = b ^ c; b = ROTL32(t,  7u);

    for(; rounds; rounds -= 2) {
        quarter( x0,  x4,  x8, x12);
        quarter( x1,  x5,  x9, x13);
        quarter( x2,  x6, x10, x14);
        quarter( x3,  x7, x11, x15);
        quarter( x0,  x5, x10, x15);
        quarter( x1,  x6, x11, x12);
        quarter( x2,  x7,  x8, x13);
        quarter( x3,  x4,  x9, x14);
    }

    X[0] += x0;   X[1] += x1;   X[2] += x2;   X[3] += x3;
    X[4] += x4;   X[5] += x5;   X[6] += x6;   X[7] += x7;
    X[8] += x8;   X[9] += x9;  X[10] += x10; X[11] += x11;
   X[12] += x12; X[13] += x13; X[14] += x14; X[15] += x15;

#undef quarter
}

/* When changing the optimal type, make sure the loops unrolled
	in _blkcopy, _blkswp and _blkxor are modified accordingly. */
#define OPTIMAL_TYPE uint4

/* Fast 32-bit / 64-bit memcpy();
 * len must be a multiple of 32 bytes */
void neoscrypt_blkcpy(void *dstp, const void *srcp, uint len) {
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i += 2) {
        dst[i]     = src[i];
        dst[i + 1] = src[i + 1];
//        dst[i + 2] = src[i + 2];
//        dst[i + 3] = src[i + 3];
    }
}
void neoscrypt_gl_blkcpy(__global void *dstp, const void *srcp, uint len) {
    __global OPTIMAL_TYPE *dst = (__global OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i += 2) {
        dst[i]     = src[i];
        dst[i + 1] = src[i + 1];
//        dst[i + 2] = src[i + 2];
//        dst[i + 3] = src[i + 3];
    }
}

/* Fast 32-bit / 64-bit block swapper;
 * len must be a multiple of 32 bytes */
void neoscrypt_blkswp(void *blkAp, void *blkBp, uint len) {
    OPTIMAL_TYPE *blkA = (OPTIMAL_TYPE *) blkAp;
    OPTIMAL_TYPE *blkB = (OPTIMAL_TYPE *) blkBp;
    OPTIMAL_TYPE t0, t1; //, t2, t3;
    uint i;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i += 2) {
        t0          = blkA[i];
        t1          = blkA[i + 1];
//        t2          = blkA[i + 2];
//        t3          = blkA[i + 3];
        blkA[i]     = blkB[i];
        blkA[i + 1] = blkB[i + 1];
//        blkA[i + 2] = blkB[i + 2];
//        blkA[i + 3] = blkB[i + 3];
        blkB[i]     = t0;
        blkB[i + 1] = t1;
//        blkB[i + 2] = t2;
//        blkB[i + 3] = t3;
    }
}

/* Fast 32-bit / 64-bit block XOR engine;
 * len must be a multiple of 32 bytes */
void neoscrypt_blkxor(void *dstp, const void *srcp, uint len) {
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i += 2) {
        dst[i]     ^= src[i];
        dst[i + 1] ^= src[i + 1];
//        dst[i + 2] ^= src[i + 2];
//        dst[i + 3] ^= src[i + 3];
    }
}

void neoscrypt_gl_blkxor(void *dstp, __global void *srcp, uint len) {
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    __global OPTIMAL_TYPE *src = (__global OPTIMAL_TYPE *) srcp;
    uint i;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i += 2) {
        dst[i]     ^= src[i];
        dst[i + 1] ^= src[i + 1];
//        dst[i + 2] ^= src[i + 2];
//        dst[i + 3] ^= src[i + 3];
    }
}

/* 32-bit / 64-bit / 128-bit optimised memcpy() */
void neoscrypt_copy(void *dstp, const void *srcp, uint len) {
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i++)
      dst[i] = src[i];

    tail = len & (sizeof(OPTIMAL_TYPE) - 1);
    if(tail) {
#if defined(cl_khr_byte_addressable_store) && !defined(FORCE_BYTE_COPY)
		uchar *dstb = (uchar *) dstp;
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstb[i] = srcb[i];
#else
		uint *dsti = (uint *) dstp;
		uint *srci = (uint *) srcp;

		for(i*= sizeof(OPTIMAL_TYPE)/ sizeof(uint); i < (len>> 2); ++i)
		  dsti[i] = srci[i];
#endif
	}
}

/* 32-bit / 64-bit / 128-bit optimised memcpy() */
void neoscrypt_gl_copy(__global uchar *dstp, const void *srcp, uint len) {
    __global OPTIMAL_TYPE *dst = (__global OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i++)
      dst[i] = src[i];

    tail = len & (sizeof(OPTIMAL_TYPE) - 1);
    if(tail) {
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstp[i] = srcb[i];
    }
}

/* 32-bit / 64-bit optimised memory erase aka memset() to zero */
void neoscrypt_erase(void *dstp, uint len) {
    const OPTIMAL_TYPE null = 0;
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i++)
      dst[i] = null;

    tail = len & (sizeof(OPTIMAL_TYPE) - 1);
    if(tail) {
#if defined(cl_khr_byte_addressable_store) && !defined(FORCE_BYTE_COPY)
        uchar *dstb = (uchar *) dstp;

        for(i = len - tail; i < len; i++)
			dstb[i] = 0u;
#else
		uint *dsti = (uint *) dstp;

		for(i*= sizeof(OPTIMAL_TYPE)/ sizeof(uint); i< (len>> 2); ++i)
			dsti[i] = 0u;
#endif
    }
}

/* 32-bit / 64-bit optimised XOR engine */
void neoscrypt_xor(void *dstp, const void *srcp, uint len) {
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i++)
      dst[i] ^= src[i];

    tail = len & (sizeof(OPTIMAL_TYPE) - 1);
    if(tail) {
#if defined(cl_khr_byte_addressable_store) && !defined(FORCE_BYTE_COPY)
        uchar *dstb = (uchar *) dstp;
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstb[i] ^= srcb[i];
#else
		uint *dsti = (uint *) dstp;
		uint *srci = (uint *) srcp;

		for(i*= sizeof(OPTIMAL_TYPE)/ sizeof(uint); i < (len>> 2); ++i)
			dsti[i]^= srci[i];
#endif
    }
}

/* BLAKE2s */

#define BLAKE2S_BLOCK_SIZE    64U
#define BLAKE2S_OUT_SIZE      32U
#define BLAKE2S_KEY_SIZE      32U

/* Parameter block of 32 bytes */
typedef struct blake2s_param_t {
    uchar digest_length;
    uchar key_length;
    uchar fanout;
    uchar depth;
    uint  leaf_length;
    uchar node_offset[6];
    uchar node_depth;
    uchar inner_length;
    uchar salt[8];
    uchar personal[8];
} blake2s_param;

/* State block of 180 bytes */
typedef struct blake2s_state_t {
    uint  h[8];
    uint  t[2];
    uint  f[2];
    uchar buf[2 * BLAKE2S_BLOCK_SIZE];
    uint  buflen;
} blake2s_state;

__constant uint blake2s_IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

__constant uchar blake2s_sigma[10][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

void blake2s_compress(blake2s_state *S, const uint *buf) {
    uint i;
    uint m[16];
    uint v[16];

    neoscrypt_copy(m, buf, 64);
    neoscrypt_copy(v, S, 32);

    v[ 8] = blake2s_IV[0];
    v[ 9] = blake2s_IV[1];
    v[10] = blake2s_IV[2];
    v[11] = blake2s_IV[3];
    v[12] = S->t[0] ^ blake2s_IV[4];
    v[13] = S->t[1] ^ blake2s_IV[5];
    v[14] = S->f[0] ^ blake2s_IV[6];
    v[15] = S->f[1] ^ blake2s_IV[7];
#define G(r,i,a,b,c,d) \
  do { \
    a = a + b + m[blake2s_sigma[r][2*i+0]]; \
    d = ROTR32(d ^ a, 16); \
    c = c + d; \
    b = ROTR32(b ^ c, 12); \
    a = a + b + m[blake2s_sigma[r][2*i+1]]; \
    d = ROTR32(d ^ a, 8); \
    c = c + d; \
    b = ROTR32(b ^ c, 7); \
  } while(0)
#define ROUND(r) \
  do { \
    G(r, 0, v[ 0], v[ 4], v[ 8], v[12]); \
    G(r, 1, v[ 1], v[ 5], v[ 9], v[13]); \
    G(r, 2, v[ 2], v[ 6], v[10], v[14]); \
    G(r, 3, v[ 3], v[ 7], v[11], v[15]); \
    G(r, 4, v[ 0], v[ 5], v[10], v[15]); \
    G(r, 5, v[ 1], v[ 6], v[11], v[12]); \
    G(r, 6, v[ 2], v[ 7], v[ 8], v[13]); \
    G(r, 7, v[ 3], v[ 4], v[ 9], v[14]); \
  } while(0)
    ROUND(0);
    ROUND(1);
    ROUND(2);
    ROUND(3);
    ROUND(4);
    ROUND(5);
    ROUND(6);
    ROUND(7);
    ROUND(8);
    ROUND(9);

  for(i = 0; i < 8; i++)
    S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
}

void blake2s_update(blake2s_state *S, const uchar *input, uint input_size) {
    uint left, fill;

    while(input_size > 0) {
        left = S->buflen;
        fill = 2 * BLAKE2S_BLOCK_SIZE - left;
        if(input_size > fill) {
            /* Buffer fill */
            neoscrypt_copy(S->buf + left, input, fill);
            S->buflen += fill;
            /* Counter increment */
            S->t[0] += BLAKE2S_BLOCK_SIZE;
            /* Compress */
            blake2s_compress(S, (uint *) S->buf);
            /* Shift buffer left */
            neoscrypt_copy(S->buf, S->buf + BLAKE2S_BLOCK_SIZE, BLAKE2S_BLOCK_SIZE);
            S->buflen -= BLAKE2S_BLOCK_SIZE;
            input += fill;
            input_size -= fill;
        } else {
            neoscrypt_copy(S->buf + left, input, input_size);
            S->buflen += input_size;
            /* Do not compress */
            input += input_size;
            input_size = 0;
        }
    }
}

void blake2s(const void *input, const uint input_size,
					   const void *key, const uchar key_size,
					   void *output, const uchar output_size) {
    uchar block[BLAKE2S_BLOCK_SIZE];
    blake2s_param P[1];
    blake2s_state S[1];

    /* Initialise */
    neoscrypt_erase(P, 32);
    P->digest_length = output_size;
    P->key_length    = key_size;
    P->fanout        = 1;
    P->depth         = 1;

    neoscrypt_erase(S, 180);
	// Initialize the state
	//neoscrypt_copy(S, blake2s_IV, 32);
	for(int i= 0; i< 8; ++i)
		S[0].h[i]= blake2s_IV[i];
    neoscrypt_xor(S, P, 32);

    neoscrypt_erase(block, BLAKE2S_BLOCK_SIZE);
    neoscrypt_copy(block, key, key_size);
    blake2s_update(S, (uchar *) block, BLAKE2S_BLOCK_SIZE);

    /* Update */
    blake2s_update(S, (uchar *) input, input_size);

    /* Finish */
    if(S->buflen > BLAKE2S_BLOCK_SIZE) {
        S->t[0] += BLAKE2S_BLOCK_SIZE;
        blake2s_compress(S, (uint *) S->buf);
        S->buflen -= BLAKE2S_BLOCK_SIZE;
        neoscrypt_copy(S->buf, S->buf + BLAKE2S_BLOCK_SIZE, S->buflen);
    }
    S->t[0] += S->buflen;
    S->f[0] = ~0U;
    neoscrypt_erase(S->buf + S->buflen, 2 * BLAKE2S_BLOCK_SIZE - S->buflen);
    blake2s_compress(S, (uint *) S->buf);

    /* Write back */
    neoscrypt_copy(output, S, output_size);
}

#define FASTKDF_BUFFER_SIZE 256U

/* FastKDF, a fast buffered key derivation function:
 * FASTKDF_BUFFER_SIZE must be a power of 2;
 * password_len, salt_len and output_len should not exceed FASTKDF_BUFFER_SIZE;
 * prf_output_size must be <= prf_key_size; */
void fastkdf(const uint4 password, const uint4 salt,
			 uint N, uchar *output, uint output_len) {
	// BLOCK_SIZE            64U
	// FASTKDF_BUFFER_SIZE  256U
	// BLAKE2S_BLOCK_SIZE    64U
	// BLAKE2S_KEY_SIZE      32U
	// BLAKE2S_OUT_SIZE      32U

    uint4 A[(FASTKDF_BUFFER_SIZE + BLAKE2S_BLOCK_SIZE)/ sizeof(uint4)],
		B[(FASTKDF_BUFFER_SIZE + BLAKE2S_KEY_SIZE)/ sizeof(uint4)];
	uchar prf_output[BLAKE2S_OUT_SIZE];
	uchar *prf_input, *prf_key, *ucBptr, *ucAptr;
    uint bufidx, a, b, i, j;

	// password_len is 4*4= 16 byte, i.e. a copy is done copying the unit4
    /* Initialise the password and salt buffer */
	{
		// Some pointers to help iterating
		uint4 *hP1= A, *hP2= B;

		// kdf_buf_size>> (sizeof(uint4)>> 2) means:
		// kdf_buf_size/ (sizeof(uint4)/ 4) but bitshifts are usually faster
#pragma unroll
		for(i = (FASTKDF_BUFFER_SIZE>> (sizeof(uint4)>> 2)); i; --i, ++hP1, ++hP2) {
			// neoscrypt_copy(&A[i * password_len], &password[0], password_len);
			*hP1= password;
			*hP2= salt;
		}

		//neoscrypt_copy(&A[FASTKDF_BUFFER_SIZE], &password[0], prf_input_size);
#pragma unroll
		for(i= BLAKE2S_BLOCK_SIZE>> (sizeof(uint4)>> 2); i; --i, ++hP1)
			*hP1= password;
#pragma unroll
		for(i= BLAKE2S_KEY_SIZE>> (sizeof(uint4)>> 2); i; --i, ++hP2)
			*hP2= salt;
	}
	ucAptr= (uchar *)A;
	ucBptr= (uchar *)B;
    /* The primary iteration */
    for(i = 0, bufidx = 0; i < N; i++) {

        /* Map the PRF input buffer */
        prf_input = &ucAptr[bufidx];

        /* Map the PRF key buffer */
        prf_key = &ucBptr[bufidx];

        /* PRF */
        blake2s(prf_input, BLAKE2S_BLOCK_SIZE,
				prf_key, BLAKE2S_KEY_SIZE,
				prf_output, BLAKE2S_OUT_SIZE);

        /* Calculate the next buffer pointer */
        for(j = 0, bufidx = 0; j< BLAKE2S_OUT_SIZE; j++)
			bufidx += prf_output[j];
        bufidx &= (FASTKDF_BUFFER_SIZE - 1);

        /* Modify the salt buffer */
        neoscrypt_xor(&ucBptr[bufidx], &prf_output[0], BLAKE2S_OUT_SIZE);

        /* Head modified, tail updated */
        if(bufidx < BLAKE2S_KEY_SIZE)
          neoscrypt_copy(&ucBptr[FASTKDF_BUFFER_SIZE + bufidx], &B[bufidx],
				min(BLAKE2S_OUT_SIZE, BLAKE2S_KEY_SIZE- bufidx));

        /* Tail modified, head updated */
        if((FASTKDF_BUFFER_SIZE - bufidx) < BLAKE2S_OUT_SIZE)
          neoscrypt_copy(ucBptr, &ucBptr[FASTKDF_BUFFER_SIZE],
				BLAKE2S_OUT_SIZE - (FASTKDF_BUFFER_SIZE - bufidx));
    }

    /* Modify and copy into the output buffer */
    if(output_len > FASTKDF_BUFFER_SIZE)
       output_len= FASTKDF_BUFFER_SIZE;

    a = FASTKDF_BUFFER_SIZE - bufidx;
    if(a >= output_len) {
        neoscrypt_xor(&ucBptr[bufidx], ucAptr, output_len);
        neoscrypt_copy(&output[0], &ucBptr[bufidx], output_len);
    } else {
        neoscrypt_xor(&ucBptr[bufidx], ucAptr, a);
        neoscrypt_xor(ucBptr, &ucAptr[a], output_len - a);
        neoscrypt_copy(&output[0], &ucBptr[bufidx], a);
        neoscrypt_copy(&output[a], ucBptr, output_len - a);
    }
}

/* FastKDF, a fast buffered key derivation function:
 * FASTKDF_BUFFER_SIZE must be a power of 2;
 * password_len, salt_len and output_len should not exceed FASTKDF_BUFFER_SIZE;
 * prf_output_size must be <= prf_key_size; */
void fastkdf_ext_salt(const uint4 password, const uchar *salt,
			 uint N, uchar *output, uint output_len) {

	// BLOCK_SIZE            64U
	// FASTKDF_BUFFER_SIZE  256U
	// BLAKE2S_BLOCK_SIZE    64U
	// BLAKE2S_KEY_SIZE      32U
	// BLAKE2S_OUT_SIZE      32U

    uint4 A[(FASTKDF_BUFFER_SIZE + BLAKE2S_BLOCK_SIZE)/ sizeof(uint4)],
		B[(FASTKDF_BUFFER_SIZE + BLAKE2S_KEY_SIZE)/ sizeof(uint4)];
	uchar prf_output[BLAKE2S_OUT_SIZE];
	uchar *prf_input, *prf_key, *ucBptr, *ucAptr;
    uint bufidx, a, b, i, j;

	// password_len is 4*4= 16 byte, i.e. a copy is done copying the unit4
    /* Initialise the password and salt buffer */
	{
		// Some pointers to help iterating
		uint4 *hP1= A;

		// kdf_buf_size>> (sizeof(uint4)>> 2) means:
		// kdf_buf_size/ (sizeof(uint4)/ 4) but bitshifts are usually faster
#pragma unroll
		for(i = (FASTKDF_BUFFER_SIZE>> (sizeof(uint4)>> 2)); i; --i, ++hP1)
			// neoscrypt_copy(&A[i * password_len], &password[0], password_len);
			*hP1= password;

		//neoscrypt_copy(&A[FASTKDF_BUFFER_SIZE], &password[0], prf_input_size);
#pragma unroll
		for(i= BLAKE2S_BLOCK_SIZE>> (sizeof(uint4)>> 2); i; --i, ++hP1)
			*hP1= password;
	}

    /* Initialise the salt buffer */
	neoscrypt_copy(B, salt, FASTKDF_BUFFER_SIZE);
    neoscrypt_copy(((uchar *)B)+ FASTKDF_BUFFER_SIZE, salt, BLAKE2S_KEY_SIZE);

	ucAptr= (uchar *)A;
	ucBptr= (uchar *)B;
    /* The primary iteration */
    for(i = 0, bufidx = 0; i < N; i++) {

        /* Map the PRF input buffer */
        prf_input = &ucAptr[bufidx];

        /* Map the PRF key buffer */
        prf_key = &ucBptr[bufidx];

        /* PRF */
        blake2s(prf_input, BLAKE2S_BLOCK_SIZE,
			prf_key, BLAKE2S_KEY_SIZE,
			prf_output, BLAKE2S_OUT_SIZE);

        /* Calculate the next buffer pointer */
        for(j = 0, bufidx = 0; j < BLAKE2S_OUT_SIZE; j++)
			bufidx += prf_output[j];
        bufidx &= (FASTKDF_BUFFER_SIZE - 1);

        /* Modify the salt buffer */
        neoscrypt_xor(&ucBptr[bufidx], &prf_output[0], BLAKE2S_OUT_SIZE);

        /* Head modified, tail updated */
        if(bufidx < BLAKE2S_KEY_SIZE)
			neoscrypt_copy(&ucBptr[FASTKDF_BUFFER_SIZE + bufidx], &B[bufidx],
				min(BLAKE2S_OUT_SIZE, BLAKE2S_KEY_SIZE - bufidx));

        /* Tail modified, head updated */
        if((FASTKDF_BUFFER_SIZE - bufidx) < BLAKE2S_OUT_SIZE)
			neoscrypt_copy(ucBptr, &ucBptr[FASTKDF_BUFFER_SIZE],
				BLAKE2S_OUT_SIZE - (FASTKDF_BUFFER_SIZE - bufidx));

    }

    /* Modify and copy into the output buffer */
    if(output_len > FASTKDF_BUFFER_SIZE)
       output_len = FASTKDF_BUFFER_SIZE;

    a = FASTKDF_BUFFER_SIZE - bufidx;
    if(a >= output_len) {
        neoscrypt_xor(&ucBptr[bufidx], ucAptr, output_len);
        neoscrypt_copy(output, &ucBptr[bufidx], output_len);
    } else {
        neoscrypt_xor(&ucBptr[bufidx], ucAptr, a);
        neoscrypt_xor(ucBptr, &ucAptr[a], output_len - a);
        neoscrypt_copy(output, &ucBptr[bufidx], a);
        neoscrypt_copy(&output[a], ucBptr, output_len - a);
    }
}


/* Configurable optimised block mixer */
void neoscrypt_blkmix(uint *X, /*uint *Y, uint r,*/ uint mixmode) {
    uint i, mixer, rounds;

    mixer  = mixmode >> 8;
    rounds = mixmode & 0xFF;

    /* NeoScrypt flow:                   Scrypt flow:
         Xa ^= Xd;  M(Xa'); Ya = Xa";      Xa ^= Xb;  M(Xa'); Ya = Xa";
         Xb ^= Xa"; M(Xb'); Yb = Xb";      Xb ^= Xa"; M(Xb'); Yb = Xb";
         Xc ^= Xb"; M(Xc'); Yc = Xc";      Xa" = Ya;
         Xd ^= Xc"; M(Xd'); Yd = Xd";      Xb" = Yb;
         Xa" = Ya; Xb" = Yc;
         Xc" = Yb; Xd" = Yd; */

/*    if(r == 1) {
        neoscrypt_blkxor(&X[0], &X[16], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[0], rounds);
        else
          neoscrypt_salsa(&X[0], rounds);
        neoscrypt_blkxor(&X[16], &X[0], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[16], rounds);
        else
          neoscrypt_salsa(&X[16], rounds);
        return;
    }*/

//    if(r == 2) {
        neoscrypt_blkxor(&X[0], &X[48], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[0], rounds);
        else
          neoscrypt_salsa(&X[0], rounds);
        neoscrypt_blkxor(&X[16], &X[0], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[16], rounds);
        else
          neoscrypt_salsa(&X[16], rounds);
        neoscrypt_blkxor(&X[32], &X[16], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[32], rounds);
        else
          neoscrypt_salsa(&X[32], rounds);
        neoscrypt_blkxor(&X[48], &X[32], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[48], rounds);
        else
          neoscrypt_salsa(&X[48], rounds);
        neoscrypt_blkswp(&X[16], &X[32], BLOCK_SIZE);
/*        return;
    }

    * Reference code for any reasonable r *
    for(i = 0; i < 2 * r; i++) {
        if(i) neoscrypt_blkxor(&X[16 * i], &X[16 * (i - 1)], BLOCK_SIZE);
        else  neoscrypt_blkxor(&X[0], &X[16 * (2 * r - 1)], BLOCK_SIZE);
        if(mixer)
          neoscrypt_chacha(&X[16 * i], rounds);
        else
          neoscrypt_salsa(&X[16 * i], rounds);
        neoscrypt_blkcpy(&Y[16 * i], &X[16 * i], BLOCK_SIZE);
    }
    for(i = 0; i < r; i++)
      neoscrypt_blkcpy(&X[16 * i], &Y[16 * 2 * i], BLOCK_SIZE);
    for(i = 0; i < r; i++)
      neoscrypt_blkcpy(&X[16 * (i + r)], &Y[16 * (2 * i + 1)], BLOCK_SIZE);*/
}



#define SCRYPT_FOUND (0xFF)
#define SETFOUND(Xnonce) output[output[SCRYPT_FOUND]++] = Xnonce

/* NeoScrypt core engine:
 * p = 1, salt = password;
 * Basic customisation (required):
 *   profile bit 0:
 *     0 = NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20;
 *     1 = Scrypt(1024, 1, 1) with Salsa20/8;
 *   profile bits 4 to 1:
 *     0000 = FastKDF-BLAKE2s;
 *     0001 = PBKDF2-HMAC-SHA256;
 *     0010 = PBKDF2-HMAC-BLAKE256;
 * Extended customisation (optional):
 *   profile bit 31:
 *     0 = extended customisation absent;
 *     1 = extended customisation present;
 *   profile bits 7 to 5 (rfactor):
 *     000 = r of 1;
 *     001 = r of 2;
 *     010 = r of 4;
 *     ...
 *     111 = r of 128;
 *   profile bits 12 to 8 (Nfactor):
 *     00000 = N of 2;
 *     00001 = N of 4;
 *     00010 = N of 8;
 *     .....
 *     00110 = N of 128;
 *     .....
 *     01001 = N of 1024;
 *     .....
 *     11110 = N of 2147483648;
 *   profile bits 30 to 13 are reserved */
__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4* restrict input,
		volatile __global uint* restrict output,
		__global uchar* padcache,
//		const uint4 midstate0,
//		const uint4 midstate16,
		const uint target)
{
#define CONSTANT_N 128
#define CONSTANT_r 2

	/* Ensure stack alignment by putting those first. */
	/* X = CONSTANT_r * 2 * BLOCK_SIZE(64)=  */
	uchar X[256];
	/* Z is a copy of X for ChaCha */
	uchar Z[256];
	/* V = CONSTANT_N * CONSTANT_r * 2 * BLOCK_SIZE */
	__global uchar *V= &padcache[CONSTANT_N * CONSTANT_r * 2 * BLOCK_SIZE*
		(get_global_id(0)% CONCURRENT_THREADS)];
	uchar outbuf[32];
	uint4 data = (uint4)(input[4].x, input[4].y, input[4].z, get_global_id(0));

    const uint mixmode = 0x14/*, stack_align = 0x40*/;
    uint i, j;

    /* X = KDF(password, salt) */
	fastkdf(data, data, 32, X, CONSTANT_r * 2 * BLOCK_SIZE);

    /* Process ChaCha 1st, Salsa 2nd and XOR them into PBKDF2 */
	neoscrypt_blkcpy(Z, X, CONSTANT_r * 2 * BLOCK_SIZE);

	/* Z = SMix(Z) */
	for(i = 0; i < CONSTANT_N; i++) {
		/* blkcpy(V, Z) */
		neoscrypt_gl_blkcpy(&V[i * (32 * CONSTANT_r)], &Z[0], CONSTANT_r * 2 * BLOCK_SIZE);
		/* blkmix(Z, Y) */
		neoscrypt_blkmix((uint *)Z, /*&Y[0], CONSTANT_r,*/ (mixmode | 0x0100));
	}
	for(i = 0; i < CONSTANT_N; i++) {
		/* integerify(Z) mod N */
		j = (32 * CONSTANT_r) * (Z[16 * (2 * CONSTANT_r - 1)] & (CONSTANT_N - 1));
		/* blkxor(Z, V) */
		neoscrypt_gl_blkxor(&Z[0], &V[j], CONSTANT_r * 2 * BLOCK_SIZE);
		/* blkmix(Z, Y) */
		neoscrypt_blkmix((uint *)Z, /*&Y[0], CONSTANT_r, */(mixmode | 0x0100));
	}

    /* X = SMix(X) */
    for(i = 0; i < CONSTANT_N; i++) {
        /* blkcpy(V, X) */
        neoscrypt_gl_blkcpy(&V[i * (32 * CONSTANT_r)], &X[0], CONSTANT_r * 2 * BLOCK_SIZE);
        /* blkmix(X, Y) */
        neoscrypt_blkmix((uint *)X, /*&Y[0], CONSTANT_r,*/ mixmode);
    }
    for(i = 0; i < CONSTANT_N; i++) {
        /* integerify(X) mod N */
        j = (32 * CONSTANT_r) * (X[16 * (2 * CONSTANT_r - 1)] & (CONSTANT_N - 1));
        /* blkxor(X, V) */
        neoscrypt_gl_blkxor(&X[0], &V[j], CONSTANT_r * 2 * BLOCK_SIZE);
        /* blkmix(X, Y) */
        neoscrypt_blkmix((uint *)X, /*&Y[0], CONSTANT_r,*/ mixmode);
    }

	/* blkxor(X, Z) */
	neoscrypt_blkxor(&X[0], &Z[0], CONSTANT_r * 2 * BLOCK_SIZE);

    /* output = KDF(password, X) */
    fastkdf_ext_salt(data, X, 32, outbuf, 32);

	bool result = (EndianSwap(output[8]) <= target);
	if (result)
		SETFOUND(get_global_id(0));
}
