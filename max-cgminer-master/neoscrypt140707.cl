/* NeoScrypt(128, 2, 1) with Salsa20/20 and ChaCha20/20 */

#define SCRYPT_FOUND (0xFF)
#define SETFOUND(Xnonce) output[output[SCRYPT_FOUND]++] = Xnonce

__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
__kernel void search(__global const uint4 * restrict input,
volatile __global uint*restrict output, __global uint4*restrict padcache,
const uint4 midstate0, const uint4 midstate16, const uint target)
{
	uint gid = get_global_id(0);
	uint4 X[8];
	uint4 tstate0, tstate1, ostate0, ostate1, tmp0, tmp1;
	
		
	bool result = (EndianSwap(ostate1.w) <= target);
	if (result)
		SETFOUND(gid);
}