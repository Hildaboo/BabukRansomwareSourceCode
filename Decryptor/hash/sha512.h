#ifndef _CIPHER_SHA512_H
#define _CIPHER_SHA512_H
#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */
    typedef struct {
        unsigned long hi, lo;
    } uint64;
    typedef unsigned int uint32;
    typedef struct {
        uint64 h[8];
        unsigned char block[128];
        int blkused;
        uint32 len[4];
    } SHA512_State;
    void SHA512_Init(SHA512_State * s);
    void SHA512_Bytes(SHA512_State * s, const void *p, int len);
    void SHA512_Final(SHA512_State * s, unsigned char *output);
    void SHA512_Simple(const void *p, int len, unsigned char *output);
#ifdef  __cplusplus
}
#endif /* __cplusplus */
#endif /* _CIPHER_SHA512_H */
