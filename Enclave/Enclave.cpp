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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */

#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */


Entry DFA[MAX_STATES*MAX_STATES] = {0};
int DFASize;
Oram_Block LinScan[MAX_STATES];
Oram_Bucket ORAM[MAX_STATES];
unsigned int posMap[MAX_STATES];
Oram_Block stash[STASH_SPACE];
int accStates[MAX_STATES];
int accepting; //0 means no, any positive number means yes and it started at the index of that number
int state;
Oram_Block row;


/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

int nextPowerOfTwo(unsigned int v){
	v--;
	v |= v >> 1;
	v |= v >> 2;
	v |= v >> 4;
	v |= v >> 8;
	v |= v >> 16;
	v++;
	return v;
}


int prepDFA(){ //our hard-coded regex: *D.?A.?R.?P.?A*
    //NOTE: code from this function is for testing only! It would not provide security in a real enclave because the code is visible to outsiders. 
    //  It would have to be loaded encrypted from outside

    //set up accepting states
    //for(int i = 0; i < 9; i++) accStates[i] = 0;
    accStates[9] = 1;
    //for(int i = 10; i < MAX_STATES; i++) accStates[i] = 0;
    
    //set up DFA outside of ORAM
    //state 0
    DFA[0].state = 1;
    DFA[0].transition = 'D';
    //for(int i = 0; i < MAX_STATES; i++){DFA[i].state = 0; DFA[i] = 0;}
    //state 1
    DFA[MAX_STATES].state = 1;
    DFA[MAX_STATES].transition = 'D';
    DFA[MAX_STATES+1].state = 3;
    DFA[MAX_STATES+1].transition = 'A';
    DFA[MAX_STATES+2].state = 2;
    DFA[MAX_STATES+2].transition = 0;
    //for(int i = MAX_STATES+3; i < 2*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 2
    DFA[2*MAX_STATES].state = 1;
    DFA[2*MAX_STATES].transition = 'D';
    DFA[2*MAX_STATES+1].state = 3;
    DFA[2*MAX_STATES+1].transition = 'A';
    //for(int i = 2*MAX_STATES+2; i < 3*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 3
    DFA[3*MAX_STATES].state = 1;
    DFA[3*MAX_STATES].transition = 'D';
    DFA[3*MAX_STATES+1].state = 5;
    DFA[3*MAX_STATES+1].transition = 'R';
    DFA[3*MAX_STATES+2].state = 4;
    DFA[3*MAX_STATES+2].transition = 0;
    //for(int i = 3*MAX_STATES+3; i < 4*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 4
    DFA[4*MAX_STATES].state = 1;
    DFA[4*MAX_STATES].transition = 'D';
    DFA[4*MAX_STATES+1].state = 5;
    DFA[4*MAX_STATES+1].transition = 'R';
    //for(int i = 4*MAX_STATES+2; i < 5*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 5
    DFA[5*MAX_STATES].state = 1;
    DFA[5*MAX_STATES].transition = 'D';
    DFA[5*MAX_STATES+1].state = 7;
    DFA[5*MAX_STATES+1].transition = 'P';
    DFA[5*MAX_STATES+2].state = 6;
    DFA[5*MAX_STATES+2].transition = 0;
    //for(int i = 5*MAX_STATES+3; i < 6*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 6
    DFA[6*MAX_STATES].state = 1;
    DFA[6*MAX_STATES].transition = 'D';
    DFA[6*MAX_STATES+1].state = 7;
    DFA[6*MAX_STATES+1].transition = 'P';
    //for(int i = 6*MAX_STATES+2; i < 7*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 7
    DFA[7*MAX_STATES].state = 1;
    DFA[7*MAX_STATES].transition = 'D';
    DFA[7*MAX_STATES+1].state = 9;
    DFA[7*MAX_STATES+1].transition = 'A';
    DFA[7*MAX_STATES+2].state = 8;
    DFA[7*MAX_STATES+2].transition = 0;
    //for(int i = 7*MAX_STATES+3; i < 8*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 8
    DFA[8*MAX_STATES].state = 1;
    DFA[8*MAX_STATES].transition = 'D';
    DFA[8*MAX_STATES+1].state = 9;
    DFA[8*MAX_STATES+1].transition = 'A';
    //for(int i = 8*MAX_STATES+2; i < 9*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 9
    DFA[9*MAX_STATES].state = 9;
    DFA[9*MAX_STATES].transition = 0;
    //for(int i = 9*MAX_STATES+1; i < 10*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //rest of space 
    //for(int i = 10*MAX_STATES; i < MAX_STATES*MAX_STATES; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    
    return 0;
}

int initDFA(int size){ //initialize or reset DFA and ORAM
    int ret = 0;
    
    DFASize = nextPowerOfTwo(size+1) - 1;
    accepting = 0;
    memset(posMap, 0, MAX_STATES*4);
    memset(ORAM, 0, MAX_STATES*sizeof(Oram_Bucket));
    memset(stash, 0, STASH_SPACE*sizeof(Oram_Block));
    state = 0;
    
    //init oram
    for(int i = 0; i < MAX_STATES; i++){
        ret += sgx_read_rand((uint8_t*)&posMap[i], sizeof(unsigned int));
        posMap[i] = posMap[i] % (DFASize/2+1);
    }
    
    //read in DFA row by row and put in ORAM
    for(int i = 0; i < MAX_STATES; i++){
        row.actualAddr = i;
        memcpy(&(row.transitions), &DFA[i*MAX_STATES], sizeof(Oram_Block) - 4);
        opOram(i, &row, 1);
    }
    
    return ret;
}

int opOram(int index, Oram_Block* block, int write){ //the actual oram ops
    
}

int opOramLinear(int index, Oram_Block* block, int write){ //
    
}

int opOramDebug(){
    
}

int opDFA(char input){ //return >0 if accepting state, 0 otherwise
        int change = 0;
        int oldAcc = accepting;
        accepting = 0;
        opOram(state, &row, 0);
        for(int i = 0; i < MAX_STATES; i++){
            change = (input == row.transitions[i].transition);
            change = (row.transitions[i].transition == 0 && !change)
            state = state*(1-change) + (change)*row.transitions[i].state;
        }
        
        for(int i = 0; i < MAX_STATES; i++){
            accepting = (accepting || state == accStates[i]);
        }
        accepting *= state;
        //printf("DEBUG: in state %d. Accepting? %d.", state, accepting);
        return accepting;
}
