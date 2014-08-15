/* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20 */

#define rotl(x,y) rotate(x,y)
#define Ch(x,y,z) bitselect(z,y,x)
#define Maj(x,y,z) Ch((x^z),y,z)
#define ROTR32(a,b) (((a) >> (b)) | ((a) << (32 - b)))
#define ROTL32(a,b) rotate(a,b)

#define STACK_ALIGN 0x40

#if (SHA256)

// unmodified from scrypt.cl
__constant uint ES[2] = { 0x00FF00FF, 0xFF00FF00 };
__constant uint K[] = {
	0x428a2f98U,
	0x71374491U,
	0xb5c0fbcfU,
	0xe9b5dba5U,
	0x3956c25bU,
	0x59f111f1U,
	0x923f82a4U,
	0xab1c5ed5U,
	0xd807aa98U,
	0x12835b01U,
	0x243185beU, // 10
	0x550c7dc3U,
	0x72be5d74U,
	0x80deb1feU,
	0x9bdc06a7U,
	0xe49b69c1U,
	0xefbe4786U,
	0x0fc19dc6U,
	0x240ca1ccU,
	0x2de92c6fU,
	0x4a7484aaU, // 20
	0x5cb0a9dcU,
	0x76f988daU,
	0x983e5152U,
	0xa831c66dU,
	0xb00327c8U,
	0xbf597fc7U,
	0xc6e00bf3U,
	0xd5a79147U,
	0x06ca6351U,
	0x14292967U, // 30
	0x27b70a85U,
	0x2e1b2138U,
	0x4d2c6dfcU,
	0x53380d13U,
	0x650a7354U,
	0x766a0abbU,
	0x81c2c92eU,
	0x92722c85U,
	0xa2bfe8a1U,
	0xa81a664bU, // 40
	0xc24b8b70U,
	0xc76c51a3U,
	0xd192e819U,
	0xd6990624U,
	0xf40e3585U,
	0x106aa070U,
	0x19a4c116U,
	0x1e376c08U,
	0x2748774cU,
	0x34b0bcb5U, // 50
	0x391c0cb3U,
	0x4ed8aa4aU,
	0x5b9cca4fU,
	0x682e6ff3U,
	0x748f82eeU,
	0x78a5636fU,
	0x84c87814U,
	0x8cc70208U,
	0x90befffaU,
	0xa4506cebU, // 60
	0xbef9a3f7U,
	0xc67178f2U, // sha256 constants upto and including this line
	0x98c7e2a2U,
	0xfc08884dU,
	0xcd2a11aeU,
	0x510e527fU,
	0x9b05688cU,
	0xC3910C8EU,
	0xfb6feee7U,
	0x2a01a605U, // 70
	0x0c2e12e0U,
	0x4498517BU,
	0x6a09e667U,
	0xa4ce148bU,
	0x95F61999U,
	0xc19bf174U,
	0xBB67AE85U,
	0x3C6EF372U,
	0xA54FF53AU,
	0x1F83D9ABU, // 80
	0x5BE0CD19U,
	0x5C5C5C5CU,
	0x36363636U,
	0x80000000U,
	0x000003FFU,
	0x00000280U,
	0x000004a0U,
	0x00000300U
};

#define EndianSwap(n) (rotl(n & ES[0], 24U)|rotl(n & ES[1], 8U))

#define Tr2(x)		(rotl(x, 30U) ^ rotl(x, 19U) ^ rotl(x, 10U))
#define Tr1(x)		(rotl(x, 26U) ^ rotl(x, 21U) ^ rotl(x, 7U))
#define Wr2(x)		(rotl(x, 25U) ^ rotl(x, 14U) ^ (x>>3U))
#define Wr1(x)		(rotl(x, 15U) ^ rotl(x, 13U) ^ (x>>10U))

#define RND(a, b, c, d, e, f, g, h, k)	\
	h += Tr1(e); 			\
	h += Ch(e, f, g); 		\
	h += k;				\
	d += h;				\
	h += Tr2(a); 			\
	h += Maj(a, b, c);

void SHA256(uint4*restrict state0,uint4*restrict state1, const uint4 block0, const uint4 block1, const uint4 block2, const uint4 block3)
{
	uint4 S0 = *state0;
	uint4 S1 = *state1;

#define A S0.x
#define B S0.y
#define C S0.z
#define D S0.w
#define E S1.x
#define F S1.y
#define G S1.z
#define H S1.w

	uint4 W[4];

	W[ 0].x = block0.x;
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[0]);
	W[ 0].y = block0.y;
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[1]);
	W[ 0].z = block0.z;
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[2]);
	W[ 0].w = block0.w;
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[3]);

	W[ 1].x = block1.x;
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[4]);
	W[ 1].y = block1.y;
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[5]);
	W[ 1].z = block1.z;
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[6]);
	W[ 1].w = block1.w;
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[7]);

	W[ 2].x = block2.x;
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[8]);
	W[ 2].y = block2.y;
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[9]);
	W[ 2].z = block2.z;
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[10]);
	W[ 2].w = block2.w;
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[11]);

	W[ 3].x = block3.x;
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[12]);
	W[ 3].y = block3.y;
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[13]);
	W[ 3].z = block3.z;
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[14]);
	W[ 3].w = block3.w;
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[76]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	W[ 0].x += Wr1(W[ 3].z) + W[ 2].y + Wr2(W[ 0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);

	W[ 0].y += Wr1(W[ 3].w) + W[ 2].z + Wr2(W[ 0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);

	W[ 0].z += Wr1(W[ 0].x) + W[ 2].w + Wr2(W[ 0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);

	W[ 0].w += Wr1(W[ 0].y) + W[ 3].x + Wr2(W[ 1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	W[ 1].x += Wr1(W[ 0].z) + W[ 3].y + Wr2(W[ 1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);

	W[ 1].y += Wr1(W[ 0].w) + W[ 3].z + Wr2(W[ 1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);

	W[ 1].z += Wr1(W[ 1].x) + W[ 3].w + Wr2(W[ 1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);

	W[ 1].w += Wr1(W[ 1].y) + W[ 0].x + Wr2(W[ 2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	W[ 2].x += Wr1(W[ 1].z) + W[ 0].y + Wr2(W[ 2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);

	W[ 2].y += Wr1(W[ 1].w) + W[ 0].z + Wr2(W[ 2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);

	W[ 2].z += Wr1(W[ 2].x) + W[ 0].w + Wr2(W[ 2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);

	W[ 2].w += Wr1(W[ 2].y) + W[ 1].x + Wr2(W[ 3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	W[ 3].x += Wr1(W[ 2].z) + W[ 1].y + Wr2(W[ 3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);

	W[ 3].y += Wr1(W[ 2].w) + W[ 1].z + Wr2(W[ 3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);

	W[ 3].z += Wr1(W[ 3].x) + W[ 1].w + Wr2(W[ 3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);

	W[ 3].w += Wr1(W[ 3].y) + W[ 2].x + Wr2(W[ 0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);

#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

	*state0 += S0;
	*state1 += S1;
}

void SHA256_fresh(uint4*restrict state0,uint4*restrict state1, const uint4 block0, const uint4 block1, const uint4 block2, const uint4 block3)
{
#define A (*state0).x
#define B (*state0).y
#define C (*state0).z
#define D (*state0).w
#define E (*state1).x
#define F (*state1).y
#define G (*state1).z
#define H (*state1).w

	uint4 W[4];

	W[0].x = block0.x;
	D= K[63] +W[0].x;
	H= K[64] +W[0].x;

	W[0].y = block0.y;
	C= K[65] +Tr1(D)+Ch(D, K[66], K[67])+W[0].y;
	G= K[68] +C+Tr2(H)+Ch(H, K[69] ,K[70]);

	W[0].z = block0.z;
	B= K[71] +Tr1(C)+Ch(C,D,K[66])+W[0].z;
	F= K[72] +B+Tr2(G)+Maj(G,H, K[73]);

	W[0].w = block0.w;
	A= K[74] +Tr1(B)+Ch(B,C,D)+W[0].w;
	E= K[75] +A+Tr2(F)+Maj(F,G,H);

	W[1].x = block1.x;
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[4]);
	W[1].y = block1.y;
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[5]);
	W[1].z = block1.z;
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[6]);
	W[1].w = block1.w;
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[7]);

	W[2].x = block2.x;
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[8]);
	W[2].y = block2.y;
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[9]);
	W[2].z = block2.z;
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[10]);
	W[2].w = block2.w;
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[11]);

	W[3].x = block3.x;
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[12]);
	W[3].y = block3.y;
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[13]);
	W[3].z = block3.z;
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[14]);
	W[3].w = block3.w;
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[76]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[15]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[16]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[17]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[18]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[19]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[20]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[21]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[22]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[23]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[24]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[25]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[26]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[27]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[28]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[29]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[30]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[31]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[32]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[33]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[34]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[35]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[36]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[37]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[38]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[39]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[40]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[41]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[42]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[43]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[44]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[45]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[46]);

	W[0].x += Wr1(W[3].z) + W[2].y + Wr2(W[0].y);
	RND(A,B,C,D,E,F,G,H, W[0].x+ K[47]);

	W[0].y += Wr1(W[3].w) + W[2].z + Wr2(W[0].z);
	RND(H,A,B,C,D,E,F,G, W[0].y+ K[48]);

	W[0].z += Wr1(W[0].x) + W[2].w + Wr2(W[0].w);
	RND(G,H,A,B,C,D,E,F, W[0].z+ K[49]);

	W[0].w += Wr1(W[0].y) + W[3].x + Wr2(W[1].x);
	RND(F,G,H,A,B,C,D,E, W[0].w+ K[50]);

	W[1].x += Wr1(W[0].z) + W[3].y + Wr2(W[1].y);
	RND(E,F,G,H,A,B,C,D, W[1].x+ K[51]);

	W[1].y += Wr1(W[0].w) + W[3].z + Wr2(W[1].z);
	RND(D,E,F,G,H,A,B,C, W[1].y+ K[52]);

	W[1].z += Wr1(W[1].x) + W[3].w + Wr2(W[1].w);
	RND(C,D,E,F,G,H,A,B, W[1].z+ K[53]);

	W[1].w += Wr1(W[1].y) + W[0].x + Wr2(W[2].x);
	RND(B,C,D,E,F,G,H,A, W[1].w+ K[54]);

	W[2].x += Wr1(W[1].z) + W[0].y + Wr2(W[2].y);
	RND(A,B,C,D,E,F,G,H, W[2].x+ K[55]);

	W[2].y += Wr1(W[1].w) + W[0].z + Wr2(W[2].z);
	RND(H,A,B,C,D,E,F,G, W[2].y+ K[56]);

	W[2].z += Wr1(W[2].x) + W[0].w + Wr2(W[2].w);
	RND(G,H,A,B,C,D,E,F, W[2].z+ K[57]);

	W[2].w += Wr1(W[2].y) + W[1].x + Wr2(W[3].x);
	RND(F,G,H,A,B,C,D,E, W[2].w+ K[58]);

	W[3].x += Wr1(W[2].z) + W[1].y + Wr2(W[3].y);
	RND(E,F,G,H,A,B,C,D, W[3].x+ K[59]);

	W[3].y += Wr1(W[2].w) + W[1].z + Wr2(W[3].z);
	RND(D,E,F,G,H,A,B,C, W[3].y+ K[60]);

	W[3].z += Wr1(W[3].x) + W[1].w + Wr2(W[3].w);
	RND(C,D,E,F,G,H,A,B, W[3].z+ K[61]);

	W[3].w += Wr1(W[3].y) + W[2].x + Wr2(W[0].x);
	RND(B,C,D,E,F,G,H,A, W[3].w+ K[62]);

#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H

	*state0 += (uint4)(K[73], K[77], K[78], K[79]);
	*state1 += (uint4)(K[66], K[67], K[80], K[81]);
}

__constant uint fixedW[64] =
{
	0x428a2f99,0xf1374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf794,
	0xf59b89c2,0x73924787,0x23c6886e,0xa42ca65c,0x15ed3627,0x4d6edcbf,0xe28217fc,0xef02488f,
	0xb707775c,0x0468c23f,0xe7e72b4c,0x49e1f1a2,0x4b99c816,0x926d1570,0xaa0fc072,0xadb36e2c,
	0xad87a3ea,0xbcb1d3a3,0x7b993186,0x562b9420,0xbff3ca0c,0xda4b0c23,0x6cd8711a,0x8f337caa,
	0xc91b1417,0xc359dce1,0xa83253a7,0x3b13c12d,0x9d3d725d,0xd9031a84,0xb1a03340,0x16f58012,
	0xe64fb6a2,0xe84d923a,0xe93a5730,0x09837686,0x078ff753,0x29833341,0xd5de0b7e,0x6948ccf4,
	0xe0a1adbe,0x7c728e11,0x511c78e4,0x315b45bd,0xfca71413,0xea28f96a,0x79703128,0x4e1ef848,
};

void SHA256_fixed(uint4*restrict state0,uint4*restrict state1)
{
	uint4 S0 = *state0;
	uint4 S1 = *state1;

#define A S0.x
#define B S0.y
#define C S0.z
#define D S0.w
#define E S1.x
#define F S1.y
#define G S1.z
#define H S1.w

	RND(A,B,C,D,E,F,G,H, fixedW[0]);
	RND(H,A,B,C,D,E,F,G, fixedW[1]);
	RND(G,H,A,B,C,D,E,F, fixedW[2]);
	RND(F,G,H,A,B,C,D,E, fixedW[3]);
	RND(E,F,G,H,A,B,C,D, fixedW[4]);
	RND(D,E,F,G,H,A,B,C, fixedW[5]);
	RND(C,D,E,F,G,H,A,B, fixedW[6]);
	RND(B,C,D,E,F,G,H,A, fixedW[7]);
	RND(A,B,C,D,E,F,G,H, fixedW[8]);
	RND(H,A,B,C,D,E,F,G, fixedW[9]);
	RND(G,H,A,B,C,D,E,F, fixedW[10]);
	RND(F,G,H,A,B,C,D,E, fixedW[11]);
	RND(E,F,G,H,A,B,C,D, fixedW[12]);
	RND(D,E,F,G,H,A,B,C, fixedW[13]);
	RND(C,D,E,F,G,H,A,B, fixedW[14]);
	RND(B,C,D,E,F,G,H,A, fixedW[15]);
	RND(A,B,C,D,E,F,G,H, fixedW[16]);
	RND(H,A,B,C,D,E,F,G, fixedW[17]);
	RND(G,H,A,B,C,D,E,F, fixedW[18]);
	RND(F,G,H,A,B,C,D,E, fixedW[19]);
	RND(E,F,G,H,A,B,C,D, fixedW[20]);
	RND(D,E,F,G,H,A,B,C, fixedW[21]);
	RND(C,D,E,F,G,H,A,B, fixedW[22]);
	RND(B,C,D,E,F,G,H,A, fixedW[23]);
	RND(A,B,C,D,E,F,G,H, fixedW[24]);
	RND(H,A,B,C,D,E,F,G, fixedW[25]);
	RND(G,H,A,B,C,D,E,F, fixedW[26]);
	RND(F,G,H,A,B,C,D,E, fixedW[27]);
	RND(E,F,G,H,A,B,C,D, fixedW[28]);
	RND(D,E,F,G,H,A,B,C, fixedW[29]);
	RND(C,D,E,F,G,H,A,B, fixedW[30]);
	RND(B,C,D,E,F,G,H,A, fixedW[31]);
	RND(A,B,C,D,E,F,G,H, fixedW[32]);
	RND(H,A,B,C,D,E,F,G, fixedW[33]);
	RND(G,H,A,B,C,D,E,F, fixedW[34]);
	RND(F,G,H,A,B,C,D,E, fixedW[35]);
	RND(E,F,G,H,A,B,C,D, fixedW[36]);
	RND(D,E,F,G,H,A,B,C, fixedW[37]);
	RND(C,D,E,F,G,H,A,B, fixedW[38]);
	RND(B,C,D,E,F,G,H,A, fixedW[39]);
	RND(A,B,C,D,E,F,G,H, fixedW[40]);
	RND(H,A,B,C,D,E,F,G, fixedW[41]);
	RND(G,H,A,B,C,D,E,F, fixedW[42]);
	RND(F,G,H,A,B,C,D,E, fixedW[43]);
	RND(E,F,G,H,A,B,C,D, fixedW[44]);
	RND(D,E,F,G,H,A,B,C, fixedW[45]);
	RND(C,D,E,F,G,H,A,B, fixedW[46]);
	RND(B,C,D,E,F,G,H,A, fixedW[47]);
	RND(A,B,C,D,E,F,G,H, fixedW[48]);
	RND(H,A,B,C,D,E,F,G, fixedW[49]);
	RND(G,H,A,B,C,D,E,F, fixedW[50]);
	RND(F,G,H,A,B,C,D,E, fixedW[51]);
	RND(E,F,G,H,A,B,C,D, fixedW[52]);
	RND(D,E,F,G,H,A,B,C, fixedW[53]);
	RND(C,D,E,F,G,H,A,B, fixedW[54]);
	RND(B,C,D,E,F,G,H,A, fixedW[55]);
	RND(A,B,C,D,E,F,G,H, fixedW[56]);
	RND(H,A,B,C,D,E,F,G, fixedW[57]);
	RND(G,H,A,B,C,D,E,F, fixedW[58]);
	RND(F,G,H,A,B,C,D,E, fixedW[59]);
	RND(E,F,G,H,A,B,C,D, fixedW[60]);
	RND(D,E,F,G,H,A,B,C, fixedW[61]);
	RND(C,D,E,F,G,H,A,B, fixedW[62]);
	RND(B,C,D,E,F,G,H,A, fixedW[63]);

#undef A
#undef B
#undef C
#undef D
#undef E
#undef F
#undef G
#undef H
	*state0 += S0;
	*state1 += S1;
}
#endif // (SHA256)

#if 0
void shittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[1].x,B[2].y,B[3].z,B[0].w);
	tmp[1] = (uint4)(B[2].x,B[3].y,B[0].z,B[1].w);
	tmp[2] = (uint4)(B[3].x,B[0].y,B[1].z,B[2].w);
	tmp[3] = (uint4)(B[0].x,B[1].y,B[2].z,B[3].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = EndianSwap(tmp[i]);

	tmp[0] = (uint4)(B[5].x,B[6].y,B[7].z,B[4].w);
	tmp[1] = (uint4)(B[6].x,B[7].y,B[4].z,B[5].w);
	tmp[2] = (uint4)(B[7].x,B[4].y,B[5].z,B[6].w);
	tmp[3] = (uint4)(B[4].x,B[5].y,B[6].z,B[7].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = EndianSwap(tmp[i]);
}

void unshittify(uint4 B[8])
{
	uint4 tmp[4];
	tmp[0] = (uint4)(B[3].x,B[2].y,B[1].z,B[0].w);
	tmp[1] = (uint4)(B[0].x,B[3].y,B[2].z,B[1].w);
	tmp[2] = (uint4)(B[1].x,B[0].y,B[3].z,B[2].w);
	tmp[3] = (uint4)(B[2].x,B[1].y,B[0].z,B[3].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i] = EndianSwap(tmp[i]);

	tmp[0] = (uint4)(B[7].x,B[6].y,B[5].z,B[4].w);
	tmp[1] = (uint4)(B[4].x,B[7].y,B[6].z,B[5].w);
	tmp[2] = (uint4)(B[5].x,B[4].y,B[7].z,B[6].w);
	tmp[3] = (uint4)(B[6].x,B[5].y,B[4].z,B[7].w);

#pragma unroll
	for(uint i=0; i<4; ++i)
		B[i+4] = EndianSwap(tmp[i]);
}

#endif

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
static void neoscrypt_chacha(uint *X, uint rounds) {
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

/* Fast 32-bit / 64-bit block swapper;
 * len must be a multiple of 32 bytes */
void neoscrypt_blkswp(void *blkAp, void *blkBp, uint len) {
    OPTIMAL_TYPE *blkA = (OPTIMAL_TYPE *) blkAp;
    OPTIMAL_TYPE *blkB = (OPTIMAL_TYPE *) blkBp;
    register OPTIMAL_TYPE t0, t1; //, t2, t3;
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

/* 32-bit / 64-bit / 128-bit optimised memcpy() */
void neoscrypt_copy(void *dstp, const void *srcp, uint len) {
    OPTIMAL_TYPE *dst = (OPTIMAL_TYPE *) dstp;
    OPTIMAL_TYPE *src = (OPTIMAL_TYPE *) srcp;
    uint i, tail;

    for(i = 0; i < (len / sizeof(OPTIMAL_TYPE)); i++)
      dst[i] = src[i];

    tail = len & (sizeof(OPTIMAL_TYPE) - 1);
    if(tail) {
        uchar *dstb = (uchar *) dstp;
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstb[i] = srcb[i];
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
        uchar *dstb = (uchar *) dstp;

        for(i = len - tail; i < len; i++)
			dstb[i] = 0u;
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
        uchar *dstb = (uchar *) dstp;
        uchar *srcb = (uchar *) srcp;

        for(i = len - tail; i < len; i++)
          dstb[i] ^= srcb[i];
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
	//neoscrypt_copy(S, blake2s_IV, 32);
	*((uint8 *)S)= *((uint8 *)blake2s_IV);
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


	// WORKSIZE 64
	// FASTKDF_BUFFER_SIZE 256
	// BLAKE2S_BLOCK_SIZE 64

    const uint stack_align = 0x40, kdf_buf_size = FASTKDF_BUFFER_SIZE,
      prf_input_size = BLAKE2S_BLOCK_SIZE, prf_key_size = BLAKE2S_KEY_SIZE,
	  prf_output_size = BLAKE2S_OUT_SIZE;
    uint bufidx, a, b, i, j;
	// hP1, hP2 is just a helper to iterate through arrays.
    uint4 *A, *hP1, *hP2, *B;
	uchar *prf_input, *prf_key, *prf_output, *ucBptr, *ucAptr;

// password_len is 4*4= 16 byte, i.e. a copy is done copying the unit4

    /* Align and set up the buffers in stack */
    uchar stack[2 * FASTKDF_BUFFER_SIZE + BLAKE2S_BLOCK_SIZE +
				BLAKE2S_KEY_SIZE + BLAKE2S_OUT_SIZE + STACK_ALIGN];
    A          = (uint4 *)&stack[stack_align & ~(stack_align - 1)];
    B          = (uint4 *)&A[(kdf_buf_size + prf_input_size)/ sizeof(uint4)];
    prf_output = (uchar *)&A[(2 * kdf_buf_size + prf_input_size + prf_key_size)/ sizeof(uint4)];

    /* Initialise the password buffer */
    //if(password_len > kdf_buf_size)
    //   password_len = kdf_buf_size;

    //a = kdf_buf_size / 16 aka password_len;
	hP1= A;
	hP2= B;
	// kdf_buf_size>> (sizeof(uint4)>> 2) means:
	// kdf_buf_size/ (sizeof(uint4)/ 4) but bitshifts are usually faster
#pragma unroll
    for(i = kdf_buf_size>> (sizeof(uint4)>> 2); i; --i, ++hP1, ++hP2) {
		// neoscrypt_copy(&A[i * password_len], &password[0], password_len);
		*hP1= password;
		*hP2= salt;
	}
    /* kdf_buf_size divides evenly by password_len, no need for this
	b = kdf_buf_size - a * password_len;
    if(b)
      neoscrypt_copy(&A[a * password_len], &password[0], b); */

	//neoscrypt_copy(&A[kdf_buf_size], &password[0], prf_input_size);
	hP1= &A[kdf_buf_size>> (sizeof(uint4)>> 2)];
	hP2= &B[kdf_buf_size>> (sizeof(uint4)>> 2)];
#pragma unroll
	for(i= prf_input_size>> (sizeof(uint4)>> 2); i; --i, ++hP1, ++hP2) {
		*hP1= password;
		*hP2= salt;
	}

    /* Initialise the salt buffer */
    //if(salt_len > kdf_buf_size)
    //  salt_len = kdf_buf_size;

    /* Done in the loop above where A is initialized.
	a = kdf_buf_size / salt_len;
    for(i = 0; i < a; i++)
      neoscrypt_copy(&B[i * salt_len], &salt[0], salt_len);

    b = kdf_buf_size - a * salt_len;
    if(b)
      neoscrypt_copy(&B[a * salt_len], &salt[0], b);
    neoscrypt_copy(&B[kdf_buf_size], &salt[0], prf_key_size); */

	ucAptr= (uchar *)A;
	ucBptr= (uchar *)B;
    /* The primary iteration */
    for(i = 0, bufidx = 0; i < N; i++) {

        /* Map the PRF input buffer */
        prf_input = &ucAptr[bufidx];

        /* Map the PRF key buffer */
        prf_key = &ucBptr[bufidx];

        /* PRF */
        blake2s(prf_input, prf_input_size, prf_key, prf_key_size, prf_output, prf_output_size);

        /* Calculate the next buffer pointer */
        for(j = 0, bufidx = 0; j < prf_output_size; j++)
			bufidx += prf_output[j];
        bufidx &= (kdf_buf_size - 1);

        /* Modify the salt buffer */
        neoscrypt_xor(&ucBptr[bufidx], &prf_output[0], prf_output_size);

        /* Head modified, tail updated */
        if(bufidx < prf_key_size)
          neoscrypt_copy(&ucBptr[kdf_buf_size + bufidx], &B[bufidx], min(prf_output_size, prf_key_size - bufidx));

        /* Tail modified, head updated */
        if((kdf_buf_size - bufidx) < prf_output_size)
          neoscrypt_copy(ucBptr, &ucBptr[kdf_buf_size], prf_output_size - (kdf_buf_size - bufidx));

    }

    /* Modify and copy into the output buffer */
    if(output_len > kdf_buf_size)
       output_len = kdf_buf_size;

    a = kdf_buf_size - bufidx;
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


/* Configurable optimised block mixer */
void neoscrypt_blkmix(uint *X, uint *Y, uint r, uint mixmode) {
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

    if(r == 1) {
        neoscrypt_blkxor(&X[0], &X[16], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[0], rounds);
        else
          neoscrypt_salsa(&X[0], rounds);
        neoscrypt_blkxor(&X[16], &X[0], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[16], rounds);
        else
          neoscrypt_salsa(&X[16], rounds);
        return;
    }

    if(r == 2) {
        neoscrypt_blkxor(&X[0], &X[48], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[0], rounds);
        else
          neoscrypt_salsa(&X[0], rounds);
        neoscrypt_blkxor(&X[16], &X[0], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[16], rounds);
        else
          neoscrypt_salsa(&X[16], rounds);
        neoscrypt_blkxor(&X[32], &X[16], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[32], rounds);
        else
          neoscrypt_salsa(&X[32], rounds);
        neoscrypt_blkxor(&X[48], &X[32], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[48], rounds);
        else
          neoscrypt_salsa(&X[48], rounds);
        neoscrypt_blkswp(&X[16], &X[32], WORKSIZE);
        return;
    }

    /* Reference code for any reasonable r */
    for(i = 0; i < 2 * r; i++) {
        if(i) neoscrypt_blkxor(&X[16 * i], &X[16 * (i - 1)], WORKSIZE);
        else  neoscrypt_blkxor(&X[0], &X[16 * (2 * r - 1)], WORKSIZE);
        if(mixer)
          neoscrypt_chacha(&X[16 * i], rounds);
        else
          neoscrypt_salsa(&X[16 * i], rounds);
        neoscrypt_blkcpy(&Y[16 * i], &X[16 * i], WORKSIZE);
    }
    for(i = 0; i < r; i++)
      neoscrypt_blkcpy(&X[16 * i], &Y[16 * 2 * i], WORKSIZE);
    for(i = 0; i < r; i++)
      neoscrypt_blkcpy(&X[16 * (i + r)], &Y[16 * (2 * i + 1)], WORKSIZE);
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
__kernel void search(__global const uint4 * restrict input,
		volatile __global uint*restrict output,
		__global uint4*restrict padcache,
		const uint4 midstate0,
		const uint4 midstate16,
		const uint target)
{
	uint gid = get_global_id(0);
//	uint4 X[8];
//	uint4 tstate0, tstate1, ostate0, ostate1, tmp0, tmp1;
	
	uint4 data = (uint4)(input[4].x,input[4].y,input[4].z,gid);
//	uint4 pad0 = midstate0, pad1 = midstate16;

#define N 128
#define r 2

    uint /*N = 128, r = 2,*/ dblmix = 1, mixmode = 0x14, stack_align = 0x40;
    uint kdf, i, j;
    uint *X, *Y, *Z, *V;
	//                                   64
    uchar stack[(N + 3) * r * 2 * WORKSIZE + STACK_ALIGN];
    /* X = r * 2 * WORKSIZE */
    X = (uint *) &stack[STACK_ALIGN & ~(stack_align - 1)];
    /* Z is a copy of X for ChaCha */
    Z = &X[32 * r];
    /* Y is an X sized temporal space */
    Y = &X[64 * r];
    /* V = N * r * 2 * WORKSIZE */
    V = &X[96 * r];

    /* X = KDF(password, salt) */
	fastkdf(data, data, 32, (uchar *) X, r * 2 * WORKSIZE);

    /* Process ChaCha 1st, Salsa 2nd and XOR them into PBKDF2; otherwise Salsa only */

    if(dblmix) {
        /* blkcpy(Z, X) */
        neoscrypt_blkcpy(&Z[0], &X[0], r * 2 * WORKSIZE);

        /* Z = SMix(Z) */
        for(i = 0; i < N; i++) {
            /* blkcpy(V, Z) */
            neoscrypt_blkcpy(&V[i * (32 * r)], &Z[0], r * 2 * WORKSIZE);
            /* blkmix(Z, Y) */
            neoscrypt_blkmix(&Z[0], &Y[0], r, (mixmode | 0x0100));
        }
        for(i = 0; i < N; i++) {
            /* integerify(Z) mod N */
            j = (32 * r) * (Z[16 * (2 * r - 1)] & (N - 1));
            /* blkxor(Z, V) */
            neoscrypt_blkxor(&Z[0], &V[j], r * 2 * WORKSIZE);
            /* blkmix(Z, Y) */
            neoscrypt_blkmix(&Z[0], &Y[0], r, (mixmode | 0x0100));
        }
    }

    /* X = SMix(X) */
    for(i = 0; i < N; i++) {
        /* blkcpy(V, X) */
        neoscrypt_blkcpy(&V[i * (32 * r)], &X[0], r * 2 * WORKSIZE);
        /* blkmix(X, Y) */
        neoscrypt_blkmix(&X[0], &Y[0], r, mixmode);
    }
    for(i = 0; i < N; i++) {
        /* integerify(X) mod N */
        j = (32 * r) * (X[16 * (2 * r - 1)] & (N - 1));
        /* blkxor(X, V) */
        neoscrypt_blkxor(&X[0], &V[j], r * 2 * WORKSIZE);
        /* blkmix(X, Y) */
        neoscrypt_blkmix(&X[0], &Y[0], r, mixmode);
    }

    if(dblmix)
      /* blkxor(X, Z) */
      neoscrypt_blkxor(&X[0], &Z[0], r * 2 * WORKSIZE);

    /* output = KDF(password, X) ,   256                    , */
    fastkdf(data, *((uint4 *)X), /*r * 2 * WORKSIZE,*/ 32, (uchar *)output, 32);

		
//	bool result = (EndianSwap(ostate1.w) <= target);
//	if (result)
		SETFOUND(gid);
}
