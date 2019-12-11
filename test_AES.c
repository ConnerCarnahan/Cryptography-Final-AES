/*********************************************************************
* Filename:      test_AES.c
* Author:        Conner Carnahan
* Copyright:     All rights reserved(?)
* Disclaimer:    This code is presented "as is" without any guarantees.
* Details:       Defines the API for the corresponding AES 128,192, and 256 implementation.
* Documentation: https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
*********************************************************************/

#include <stdlib.h>
#include <memory.h>
#include "AES.h"
#include <string.h>
#include <stdio.h>

int main(){

    printf("Running AES 128 \n \n");
    uint32_t key[4];
    LoadKey(key, "000102030405060708090a0b0c0d0e0f"); //Load the selected Key
    
    uint32_t w[4*(14+1)];
    
    AES_state state;
    LoadKey(state.digest, "00112233445566778899aabbccddeeff"); //Load the initial buffer
    state.round = 0; //Make sure the round doesnt have garbage
    
    printf("Input State: \n");
    AES_PrintOutput(state.digest, 4);
    PrintState(&state);
    
    AES_KeyExpansion(key,w,4,10);
    AES_Cipher( key, &state, AES_a, AES_sbox, 1, 10, w);
    
    printf("Ciphered State: \n");
    AES_PrintOutput(state.digest, 4);
    PrintState(&state);
    
    AES_DW(w,10);
    AES_Cipher(key, &state, AES_ainv, AES_invsbox, 3, 10, w);
    
    printf("Deciphered State: \n");
    AES_PrintOutput(state.digest, 4);	    
    PrintState(&state);

    printf("Running AES 192 \n \n");
    uint32_t key2[6];
    LoadKey(key2, "000102030405060708090a0b0c0d0e0f1011121314151617"); //Load the selected Key
    printf("Key: \n");
    AES_PrintOutput(key2,6);

    LoadKey(state.digest, "00112233445566778899aabbccddeeff"); //Load the initial buffer
    state.round = 0; //Make sure the round doesnt have garbage
    
    printf("Input State: \n");
    AES_PrintOutput(state.digest, 4);
    PrintState(&state);
    
    AES_KeyExpansion(key2,w,6,12);
    AES_Cipher(key2, &state, AES_a, AES_sbox, 1, 12, w);
    
    printf("Ciphered State: \n");
    AES_PrintOutput(state.digest, 4);
    PrintState(&state);
    
    AES_DW(w,12);
    AES_Cipher(key2, &state, AES_ainv, AES_invsbox, 3, 12, w);
    
    printf("Deciphered State: \n");
    
    PrintState(&state);
    AES_PrintOutput(state.digest, 4);	

    printf("Running AES 256 \n \n");
    uint32_t key3[8];
    LoadKey(key3, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); //Load the selected Key
    printf("Key: \n");
    AES_PrintOutput(key3,8);

    LoadKey(state.digest, "00112233445566778899aabbccddeeff"); //Load the initial buffer
    state.round = 0; //Make sure the round doesnt have garbage
    
    printf("Input State: \n");
    AES_PrintOutput(state.digest, 4);
    PrintState(&state);
    
    AES_KeyExpansion(key3,w,8,14);
    AES_Cipher(key3, &state, AES_a, AES_sbox, 1, 14, w);
    
    printf("Ciphered State: \n");
    AES_PrintOutput(state.digest, 4);
    PrintState(&state);
    
    AES_DW(w,14);
    AES_Cipher(key3, &state, AES_ainv, AES_invsbox, 3, 14, w);
    
    printf("Deciphered State: \n");
    AES_PrintOutput(state.digest, 4);	    
    PrintState(&state);

    return 0;
}
