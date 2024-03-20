#include <iostream>
#include <memory>
#include <stdio.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <libbase64.h>

#include "aes.h"
#include "aes_helper.h"

void printHex(uint8_t *ptr,int len,char *tag)
{
	printf("%s data[%d]:", tag, len);
	int32_t i = 0;
	for (i = 0; i < len; i++)
	{
		printf("%.2X", *(ptr + i));
	}
	printf("\n");
}

TEST(AesTest, TEST_001) {

    uint8_t i =0;
    uint8_t key[16] = {0x78, 0x24, 0x0c, 0xc5, 0x59, 0x6b, 0x75, 0x1d,
                       0x90, 0x02, 0x38, 0x27, 0xb0, 0xb7, 0xe7, 0x3d};   
    uint8_t out_buf[4] = {0};
    uint8_t buf[16] = {0};
    uint8_t pre_buf[4] = {0x1,0x2,0x3,0x4}; 
    uint8_t b64_out[1024] = {0};
    size_t b64_len;

    printHex(pre_buf,sizeof(pre_buf), (char*)"pre_data");
    printHex(key,sizeof(key), (char*)"key");

    //填充
    (void)AES_pad(pre_buf, sizeof(pre_buf), buf);
    printHex(buf,sizeof(buf), (char*)"pad_data");

    (void)AES_en(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Enc_AesCbc");

    // 以base64编码形式打印
    (void)base64_encode((char*)buf, sizeof(buf), (char*)b64_out, &b64_len, 0);
    std::cout << b64_out << std::endl;

    //裁剪
    (void)AES_cut(buf, sizeof(buf), out_buf);
    printHex(out_buf, sizeof(out_buf), (char *)std::string("cut_data").c_str());
    
    (void)AES_de(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char *)"Dec_AesCbc");
}

TEST(AesTest, TEST_002) {

    uint8_t i =0;
    uint8_t key[16] = {0x78, 0x24, 0x0c, 0xc5, 0x59, 0x6b, 0x75, 0x1d,
                       0x90, 0x02, 0x38, 0x27, 0xb0, 0xb7, 0xe7, 0x3d};   
    uint8_t out_buf[4] = {0};
    uint8_t buf[16] = {0};
    uint8_t pre_buf[4] = {0x00,0x00,0x00,0x00}; 
    uint8_t b64_out[1024] = {0};
    size_t b64_len;

    printHex(pre_buf,sizeof(pre_buf), (char*)"pre_data");
    printHex(key,sizeof(key), (char*)"key");

    //填充
    (void)AES_pad(pre_buf, sizeof(pre_buf), buf);
    printHex(buf,sizeof(buf), (char*)"pad_data");

    (void)AES_en(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Enc_AesCbc");

    // 以base64编码形式打印
    (void)base64_encode((char*)buf, sizeof(buf), (char*)b64_out, &b64_len, 0);
    std::cout << b64_out << std::endl;

    //裁剪
    (void)AES_cut(buf, sizeof(buf), out_buf);
    printHex(out_buf,sizeof(out_buf), (char*)"cut_data");
    
    (void)AES_de(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Dec_AesCbc");
}

TEST(AesTest, TEST_003) {

    uint8_t i =0;
    uint8_t key[16] = {0x78, 0x24, 0x0c, 0xc5, 0x59, 0x6b, 0x75, 0x1d, 0x90, 0x02, 0x38, 0x27, 0xb0, 0xb7, 0xe7, 0x3d};   
    uint8_t out_buf[4] = {0};
    uint8_t buf[16] = {0};
    uint8_t pre_buf[4] = {0x01,0x02,0x00,0x00}; 
    uint8_t b64_out[1024] = {0};
    size_t b64_len;

    printHex(pre_buf,sizeof(pre_buf), (char*)"pre_data");
    printHex(key,sizeof(key), (char*)"key");

    //填充
    (void)AES_pad(pre_buf, sizeof(pre_buf), buf);
    printHex(buf,sizeof(buf), (char*)"pad_data");

    (void)AES_en(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Enc_AesCbc");

    // 以base64编码形式打印
    (void)base64_encode((char*)buf, sizeof(buf), (char*)b64_out, &b64_len, 0);
    std::cout << b64_out << std::endl;

    //裁剪
    (void)AES_cut(buf, sizeof(buf), out_buf);
    printHex(out_buf,sizeof(out_buf), (char*)"cut_data");
    
    (void)AES_de(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Dec_AesCbc");
}

TEST(AesTest, TEST_004) {

    uint8_t i =0;
    uint8_t key[16] = {0x78, 0x24, 0x0c, 0xc5, 0x59, 0x6b, 0x75, 0x1d, 0x90, 0x02, 0x38, 0x27, 0xb0, 0xb7, 0xe7, 0x3d};   
    uint8_t out_buf[4] = {0};
    uint8_t buf[16] = {0};
    uint8_t pre_buf[8] = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x08}; 
    uint8_t b64_out[1024] = {0};
    size_t b64_len;

    printHex(pre_buf,sizeof(pre_buf), (char*)"pre_data");
    printHex(key,sizeof(key), (char*)"key");

    //填充
    (void)AES_pad(pre_buf, sizeof(pre_buf), buf);
    printHex(buf,sizeof(buf), (char*)"pad_data");

    (void)AES_en(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Enc_AesCbc");

    // 以base64编码形式打印
    (void)base64_encode((char*)buf, sizeof(buf), (char*)b64_out, &b64_len, 0);
    std::cout << b64_out << std::endl;

    //裁剪
    (void)AES_cut(buf, sizeof(buf), out_buf);
    printHex(out_buf,sizeof(out_buf), (char*)"cut_data");
    
    (void)AES_de(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Dec_AesCbc");
}

TEST(AesTest, TEST_005) {

    uint8_t i =0;
    uint8_t key[16] = {0x78, 0x24, 0x0c, 0xc5, 0x59, 0x6b, 0x75, 0x1d, 0x90, 0x02, 0x38, 0x27, 0xb0, 0xb7, 0xe7, 0x3d};   
    uint8_t out_buf[4] = {0};
    uint8_t buf[16] = {0};
    uint8_t pre_buf[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08}; 
    uint8_t b64_out[1024] = {0};
    size_t b64_len;

    printHex(pre_buf,sizeof(pre_buf), (char*)"pre_data");
    printHex(key,sizeof(key), (char*)"key");

    //填充
    (void)AES_pad(pre_buf, sizeof(pre_buf), buf);
    printHex(buf,sizeof(buf), (char*)"pad_data");

    (void)AES_en(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Enc_AesCbc");

    // 以base64编码形式打印
    (void)base64_encode((char*)buf, sizeof(buf), (char*)b64_out, &b64_len, 0);
    std::cout << b64_out << std::endl;

    //裁剪
    (void)AES_cut(buf, sizeof(buf), out_buf);
    printHex(out_buf,sizeof(out_buf), (char*)"cut_data");
    
    (void)AES_de(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Dec_AesCbc");
}

TEST(AesTest, TEST_006) {

    uint8_t i =0;
    uint8_t key[16] = {0x78, 0x24, 0x0c, 0xc5, 0x59, 0x6b, 0x75, 0x1d, 0x90, 0x02, 0x38, 0x27, 0xb0, 0xb7, 0xe7, 0x3d};   
    uint8_t out_buf[4] = {0};
    uint8_t buf[16] = {0};
    uint8_t pre_buf[8] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x00}; 
    uint8_t b64_out[1024] = {0};
    size_t b64_len;

    printHex(pre_buf,sizeof(pre_buf), (char*)"pre_data");
    printHex(key,sizeof(key), (char*)"key");

    //填充
    (void)AES_pad(pre_buf, sizeof(pre_buf), buf);
    printHex(buf,sizeof(buf), (char*)"pad_data");

    (void)AES_en(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Enc_AesCbc");

    // 以base64编码形式打印
    (void)base64_encode((char*)buf, sizeof(buf), (char*)b64_out, &b64_len, 0);
    std::cout << b64_out << std::endl;

    //裁剪
    (void)AES_cut(buf, sizeof(buf), out_buf);
    printHex(out_buf,sizeof(out_buf), (char*)"cut_data");
    
    (void)AES_de(buf, sizeof(buf), key);
    printHex(buf,sizeof(buf), (char*)"Dec_AesCbc");
}
