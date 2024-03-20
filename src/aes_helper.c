#include <string.h>
#include "aes_helper.h"
#include "aes.h"

void AES_en(uint8_t *data, uint8_t len, uint8_t *key)
{
    uint8_t iv[16] = {
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};

    AES_KEY aes;
    if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0) {
        return;
    }

    AES_cbc_encrypt(data, data, len, &aes, iv, AES_ENCRYPT);
}

void AES_de(uint8_t *data, uint8_t len, uint8_t *key)
{
    uint8_t iv[16] = {
	   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
    AES_KEY aes;
    if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0) {
        return;
    }

    AES_cbc_encrypt(data, data, len, &aes, iv, AES_DECRYPT);
}

void AES_pad(uint8_t *inData, uint8_t len, uint8_t *outData)
{
    uint8_t ghost = 0;
    int8_t i = 0;

    if(!inData || !outData)
    {
        return;
    }

    for(i = len - 1; i >= 0; i--)
    {
        if(inData[i] != 0)
        {
            ghost = inData[i];
            break;
        }
    }
    ghost = ghost ^ 255;
    for(i = 0; i < 16; i++)
    {
        if(i <= 3 )
        {
            outData[i] = inData[i];
        }
        else if(i < 12)
        {
            outData[i] = ghost;
        }
        else
        {
            outData[i] = outData[15-i];
        }
    }
}

void AES_cut(uint8_t *inData, uint8_t len, uint8_t *outData)
{
    uint8_t i = 0;
    uint8_t tmp_out[16] = {0};

    if(!inData || !outData)
    {
        return;
    }

    (void)memcpy(tmp_out, inData, len);
    for(i = 0; i < 4; i++)
    {
        tmp_out[i] = tmp_out[i] ^ tmp_out[i+4];
        tmp_out[i+4] = tmp_out[i+8] ^ tmp_out[i+12];
    }
    for(i = 0; i < 2; i++)
    {
        outData[i] = tmp_out[i] ^ tmp_out[i+4];
        outData[i+2] = tmp_out[i+2] ^ tmp_out[i+6];
    }
}
