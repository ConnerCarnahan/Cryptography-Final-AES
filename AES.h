
/*********************************************************************
* Filename:   AES.h
* Author:     Conner Carnahan
* Copyright:  All rights reserved(?)
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding AES implementation.
*********************************************************************/

#include <ctype.h>


#ifndef AES_H
#define AES_H

/*************************** HEADER FILES ***************************/

/****************************** Constants ******************************/

#define AES_DIGEST_SIZE 4
#define NUM_ROUNDS 10
#define AES_a 0x03010102
#define AES_ainv 0x0b0d090e

/****************************** TYPES ******************************/


typedef struct {
	uint32_t digest[AES_DIGEST_SIZE];
  uint8_t round;
} AES_state;

/*********************** FUNCTION DECLARATIONS **********************/

uint8_t AES_multCoef(uint8_t a, uint8_t b);
void AES_multColumn(uint32_t a, uint32_t b, uint32_t* c);
void AES_xtimes(uint8_t a, uint8_t* b);
uint8_t AES_getByte(uint32_t, uint8_t n);
void AES_ShiftRows(AES_state* state, uint8_t shiftnum);
void AES_SubBytes(AES_state* state, uint8_t* table);
uint32_t AES_SubColumn(uint32_t col, uint8_t* table);
void AES_KeyExpansion(uint32_t* key, uint32_t* w, uint8_t Nk, uint8_t Nr);
void AES_Cipher(uint32_t* key, AES_state* state, uint32_t ax, uint8_t* table, uint8_t shiftnum, uint8_t Nk, uint8_t Nr);
void AES_AddRoundKey(AES_state* state, uint32_t* w);
void AES_MixColumns(AES_state* state, uint32_t ax);

#endif   // AES_H

static inline uint8_t hex2bin(char c) {
  if ('0' <= c && c <= '9')
    return c - '0';
  else
    return tolower(c)-'a' + 0xa;
}