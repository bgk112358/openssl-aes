#ifndef AES_HELPER_H
# define AES_HELPER_H

#include <stdio.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
 
/* 测试接口 */
void AES_en(uint8_t *data, uint8_t len, uint8_t *key);
void AES_de(uint8_t *data, uint8_t len, uint8_t *key);

/* 补位功能 */
void AES_pad(uint8_t *inData, uint8_t len, uint8_t *outData);

/* 裁剪功能 */
void AES_cut(uint8_t *inData, uint8_t len, uint8_t *outData);
 
#ifdef __cplusplus
}
#endif

#endif // AES_HELPER_H