#if (__cplusplus)
extern "C" {
#endif

/* These routines are always available. */
extern void neoscrypt_regenhash(struct work *work);
extern void neoscrypt(const unsigned char *input, unsigned char *output, unsigned int profile);

#if (__cplusplus)
}
#endif
