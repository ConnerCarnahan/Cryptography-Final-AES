/*********************************************************************
* Filename:   AES.c
* Author:     Conner Carnahan
* Copyright:  All rights reserved(?)
* Disclaimer: This code is presented "as is" without any guarantees.
*
* Implementation of the Advanced Encryption Standard Algroithm
* Documentation is provided here: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
* 
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "AES.h"

/*********************** Implementations ***********************/

/// a x b in GF(2^8)
uint8_t AES_multCoef(uint8_t a, uint8_t b){
	uint8_t A = a;
	uint8_t B = b;
	
	// Loop multiplies A by x each time and then will add it to the running total if B has a coefficient of 1 in that place
	// This works because multiplication is linear and can be expanded into coefficients * basis elements added together
	uint8_t c = (0x1&B)*A;
	B >>= 1;
	while (B > 0){
		AES_xtimes(A,&A);
		c = c ^ (0x1&B)*A;
		B >>= 1;
	}
	return c;
}

// b = a x 2
void AES_xtimes(uint8_t a, uint8_t* b){
	if ((a & 0x80) != 0x80){
		b[0] = (uint8_t) a << 1;
	}
	else {
		b[0] = (uint8_t) ((a << 1) ^ 0x1b);
	}
}

/// a x b in the ring of 4th degree polynomials over GF(2^8)
uint32_t AES_multColumn(uint32_t a, uint32_t b){
	uint32_t A = a;
	uint32_t c = 0;

	// There is a cyclic pattern with the matrix you multiply by, so I realized I could just start at the bottom 
	// and go up while rotating the matrix word
	for (int i = 0; i < 4; i++){
		c <<= 8;
		c |= AES_multCoef(AES_getByte(A,3), AES_getByte(b,0))^AES_multCoef(AES_getByte(A,2), AES_getByte(b,1))
			^AES_multCoef(AES_getByte(A,1), AES_getByte(b,2))^AES_multCoef(AES_getByte(A,0), AES_getByte(b,3));
		A = (A >> 24) | (A << 8);
	}
	return c;

}

/// Performs the ShiftRows function described in the AES Documentation
/// Considers the State as rows of bytes and will shift them by the shiftnum*row mod 4
void AES_ShiftRows(AES_state* state, uint8_t shiftnum){
	uint32_t columns[4] = {0,0,0,0};
	for (int i = 0; i < 4; i ++){
		uint32_t mask = 0xff;
		for(int j = 0; j < 4; j ++){
			// Shifts the mask around to get the correct byte in the column that is shifted appropriately
			columns[i] |= (state->digest[(i+shiftnum*j)&3])&mask;
			mask <<= 8;
		}
	}
	for (int i = 0; i < 4; i++){
		state->digest[i] = columns[i];
	}
}

/// Performs the SubBytes function described in the AES Documentation
/// Substitutes bytes in the state box accoreding to a table that is provided
/// table should be sbox for Ciphering and invsbox for deciphering
void AES_SubBytes(AES_state* state, const uint8_t* table){
	for (int i = 0; i < 4; i++){
		uint32_t res = 0;
		for (int j = 0; j< 4; j++) {
			// The table is 16x16 so the first Nibble gives the row, second gives the column
			res |= ((uint32_t) table[AES_getByte(state->digest[i],j)]) << (j << 3);
		}
		state->digest[i] = res;
	}
}

/// Performs the SubBytes function described in the AES Documentation but only on one 32 bit number
/// Col is the number to be subbed, table is the table subbing is according to
uint32_t AES_SubColumn(uint32_t col, const uint8_t* table){
	uint32_t res = 0;
	for (int j = 0; j < 4; j++) {
		res |= ((uint32_t) table[AES_getByte(col,j)]) << (j << 3); // The table is 16x16 so the first Nibble gives the row, second gives the column
	}
	return res;
}

/// Performs the Mix Columns function described in the AES Documentation
/// State is the current state of the AES Box, ax is a polynomial represented as a 32 bit number which will
/// be multiplied to the state columns
void AES_MixColumns(AES_state* state, uint32_t ax){
	for (int i = 0; i < 4; i++ ){
		state->digest[i] = AES_multColumn(ax,state->digest[i]);
	}
}

/// Add Round key Described in the AES Documentation
/// XORs the columns with the corresponding Key Register columns for the current round
void AES_AddRoundKey(AES_state* state, uint32_t* w){
	for (int i = 0; i < 4; i++){
		state->digest[i] = state->digest[i]^w[4*state->round+i];
	}
	state->round += 1;
}

//Variable key size Key expansion into the key register
//Key is the key, w is the memory address of the key register, Nk is the number of words in the key, Nr is the number of rounds
void AES_KeyExpansion(uint32_t* key, uint32_t* w, uint8_t Nk, uint8_t Nr){
	int i = 0;
	uint32_t temp;

	while (i < Nk){
		w[i] = key[i]; // The key is the first Nkth bytes
		i++;
	}
	
	while (i < 4*(Nr+1)){
		temp = w[i-1];
		if (i % Nk == 0){
			// The way I did my endians made it so I actually rotate the opposite way to get the right result (aka rotate right)
			// Also Rcon had to be backwards
			temp = AES_SubColumn((temp >> 8) | (temp << 24),AES_sbox) ^ AES_Rcon[i/Nk - 1];
		} else if (Nk > 6 && i % Nk == 4){
			temp = AES_SubColumn(temp,AES_sbox);
		}
		w[i] = w[i - Nk] ^ temp;
		i++;
	}
}

//Creates the manipulated Key Register for deciphering
void AES_DW(uint32_t* w, uint8_t Nr){
	uint32_t dw[4*(Nr+1)]; // This will be the new key register but in backwards order (with 4x32 blocks in the same order)
	for(int j = 0; j < 4; j++){
		dw[j] = w[4*(Nr)+j]; // On the first and last blocks we don't multiply by ainv
	}
	for (int i = 1; i < Nr; i++){
		for(int j = 0; j < 4; j++){
			dw[4*i+j] = AES_multColumn(AES_ainv,w[4*(Nr-i)+j]); // Multiply each word by ainv
		}
	}
	for (int i = 0 ; i < 4; i++){
		dw[4*Nr+i] = w[i]; //Final load
	}
	for (int i = 0; i < 4*(Nr+1); i++){
		w[i] = dw[i]; //Load in the new values for w
	}
}

/// Ciphers or Deciphers the state digest as described in the AES Documentation
/// For Ciphering: ax = AES_a, table = sbox, shiftnum = 1
/// For Deciphering: ax = AES_ainv, table = invsbox, shiftnum = 3
/// Nr is the number of rounds
/// For the output refer to the final state digest
void AES_Cipher(uint32_t* key, AES_state* state, uint32_t ax, const uint8_t* table, uint8_t shiftnum, uint8_t Nr, uint32_t* w){
	int i = 0;
	
	AES_AddRoundKey(state,w);
	
	while (i < Nr-1){
		AES_SubBytes(state,table);
		AES_ShiftRows(state,shiftnum);
		AES_MixColumns(state,ax);
		AES_AddRoundKey(state,w);
		i+=1;
	}
	
	AES_SubBytes(state,table);
	AES_ShiftRows(state,shiftnum);
	AES_AddRoundKey(state,w);
	
	state->round = 0;
}

/// Find the (n-1)th byte in the word
uint8_t AES_getByte(uint32_t a, uint8_t n){
	return (uint8_t) (a >> ((n) << 3));
}

/// Prints the current digest of the state in block form
void PrintState(AES_state* state){
    printf("State Value \n");
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            printf("%02x ",AES_getByte(state->digest[j],i));
        }
        printf("\n");
    }
    printf("\n");
}

/// Prints the value of the key register (w) at round (round) in block form
void PrintRegister(uint32_t* w, uint8_t round){
    printf("Register value \n");
    for (int i = 0; i < 4; i++){
        for (int j = 0; j < 4; j++){
            printf("%02x ",AES_getByte(w[4*round+j],i));
        }
        printf("\n");
    }
    printf("\n");
}


/// Loads in hexdigits from a string into an array "key". 
/// This does work for initiallizing states but be careful you don't type too little / too much
void LoadKey(uint32_t* key, char* s){
    int count = strlen(s);
    int i = 0;
    uint32_t dat = 0;
    uint32_t bytes = 0;
    uint32_t nibbles = 0;
    while (i < count){
        if (!isspace(s[i])){
            if((nibbles&1)==0){
                dat = hex2bin(s[i]) << 4;
                nibbles+=1;
            } else {
                dat |= hex2bin(s[i]);
                nibbles+=1;
                key[(bytes>>2)] |= dat << (bytes << 3);
                bytes += 1;
            }
        }
        i+=1;
    }
}

void AES_PrintOutput(uint32_t* digest, uint8_t size){
	printf("Output: \n");
	for (int i = 0; i < size; i++){
		for(int j = 0; j < 4 ; j++)
		printf("%02x", AES_getByte(digest[i], j));
	}
	printf("\n\n");
}