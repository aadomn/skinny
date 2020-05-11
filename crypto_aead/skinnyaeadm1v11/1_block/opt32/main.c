#include "crypto_aead.h"
#include <stdio.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned int u32;

int main() {

    u8 ptext[32];
    u8 ctext[48];
    u8 ad[32];
    u8 nonce[16];
    u8 key[16];

    for(int i = 0; i < 16; i++) {
        nonce[i] = i;
        key[i] = i;
    }
    for(int i = 0; i < 32; i++) {
        ptext[i] = i;
        ad[i] = i;
    }

    printf("Encryption\n");
    unsigned long long clen;
    memset(ctext, 0x00, sizeof(ctext));
    crypto_aead_encrypt(ctext, &clen, ptext, 0, ad, 0, NULL, nonce, key);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ctext[0], ctext[1], ctext[2], ctext[3], ctext[4], ctext[5], ctext[6], ctext[7]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ctext[8], ctext[9], ctext[10], ctext[11], ctext[12], ctext[13], ctext[14], ctext[15]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ctext[16], ctext[17], ctext[18], ctext[19], ctext[20], ctext[21], ctext[22], ctext[23]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ctext[24], ctext[25], ctext[26], ctext[27], ctext[28], ctext[29], ctext[30], ctext[31]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ctext[32], ctext[33], ctext[34], ctext[35], ctext[36], ctext[37], ctext[38], ctext[39]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ctext[40], ctext[41], ctext[42], ctext[43], ctext[44], ctext[45], ctext[46], ctext[47]);
    
    memset(ptext, 0x00, 32);
    int ret = crypto_aead_decrypt(ptext, &clen,NULL, ctext, clen, ad, 0, nonce, key);
    printf("Decryption returns %d\n",ret);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ptext[0], ptext[1], ptext[2], ptext[3], ptext[4], ptext[5], ptext[6], ptext[7]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ptext[8], ptext[9], ptext[10], ptext[11], ptext[12], ptext[13], ptext[14], ptext[15]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ptext[16], ptext[17], ptext[18], ptext[19], ptext[20], ptext[21], ptext[22], ptext[23]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ptext[24], ptext[25], ptext[26], ptext[27], ptext[28], ptext[29], ptext[30], ptext[31]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ptext[32], ptext[33], ptext[34], ptext[35], ptext[36], ptext[37], ptext[38], ptext[39]);
    printf("%02x %02x %02x %02x %02x %02x %02x %02x\n", ptext[40], ptext[41], ptext[42], ptext[43], ptext[44], ptext[45], ptext[46], ptext[47]);
    //printf("%d\n",ret);

    return 0;
}