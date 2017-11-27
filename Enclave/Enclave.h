/*
 * Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _ENCLAVE_H_
#define _ENCLAVE_H_

#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <math.h>
#include "string.h"
#include "sgx_trts.h"


#if defined(__cplusplus)
extern "C" {
#endif
    
#define MAX_STATES 511 //size of block in terms of entries
#define BUCKET_SIZE 4
#define STASH_SPACE 128 //should be something like 90+4*log_2(MAX_STATES) for 2^-80 prob of failure on each access, but make it a power of 2
    
typedef struct{
    char transition;
    uint8_t state;
} Entry;
    
typedef struct{
	int actualAddr;
	Entry transitions[256];//possibility of a different transition for each symbol
	unsigned int leaf; //we have each block keep track of its leaf to avoid a bunch of linear scans of the posMap
} Oram_Block;

typedef struct{
	Oram_Block blocks[BUCKET_SIZE];
} Oram_Bucket;

extern Entry DFA[MAX_STATES*256];
extern Oram_Bucket ORAM[MAX_STATES];
extern unsigned int posMap[MAX_STATES];
extern Oram_Block stash[2*STASH_SPACE];
extern int accStates[MAX_STATES];
extern int accepting; //0 means no, any positive number means yes and it started at the index of that number
extern Oram_Block row;

int nextPowerOfTwo(unsigned int num);
void printf(const char *fmt, ...);

int prepDFA(); //prepare DFA for reading in (only needs to be run once)
int initDFA(); //start up or reboot the DFA
int opOram(int index, Oram_Block* block, int write);
void sortStash(int startIndex, int size, int flipped);
void mergeStash(int startIndex, int size, int flipped);
int opDFA(char input); //return >=1 if accepting state, 0 otherwise
int runDFA(char* data, int length); //return last op output

#if defined(__cplusplus)
}
#endif

#endif /* !_ENCLAVE_H_ */
