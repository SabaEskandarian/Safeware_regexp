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


Entry DFA[MAX_STATES*256] = {0};
Oram_Bucket ORAM[MAX_STATES];
unsigned int posMap[MAX_STATES];
Oram_Block stash[2*STASH_SPACE];
int accStates[MAX_STATES];
int accepting; //0 means no, any positive number means yes and it started at the index of that number
int state;
Oram_Block row; //use this inside opOram and functions it calls
Oram_Block block; //use this outside opOram


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
    //for(int i = 0; i < 256; i++){DFA[i].state = 0; DFA[i] = 0;}
    //state 1
    DFA[256].state = 1;
    DFA[256].transition = 'D';
    DFA[256+1].state = 3;
    DFA[256+1].transition = 'A';
    DFA[256+2].state = 2;
    DFA[256+2].transition = 0;
    //for(int i = 256+3; i < 2*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 2
    DFA[2*256].state = 1;
    DFA[2*256].transition = 'D';
    DFA[2*256+1].state = 3;
    DFA[2*256+1].transition = 'A';
    //for(int i = 2*256+2; i < 3*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 3
    DFA[3*256].state = 1;
    DFA[3*256].transition = 'D';
    DFA[3*256+1].state = 5;
    DFA[3*256+1].transition = 'R';
    DFA[3*256+2].state = 4;
    DFA[3*256+2].transition = 0;
    //for(int i = 3*256+3; i < 4*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 4
    DFA[4*256].state = 1;
    DFA[4*256].transition = 'D';
    DFA[4*256+1].state = 5;
    DFA[4*256+1].transition = 'R';
    //for(int i = 4*256+2; i < 5*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 5
    DFA[5*256].state = 1;
    DFA[5*256].transition = 'D';
    DFA[5*256+1].state = 7;
    DFA[5*256+1].transition = 'P';
    DFA[5*256+2].state = 6;
    DFA[5*256+2].transition = 0;
    //for(int i = 5*256+3; i < 6*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 6
    DFA[6*256].state = 1;
    DFA[6*256].transition = 'D';
    DFA[6*256+1].state = 7;
    DFA[6*256+1].transition = 'P';
    //for(int i = 6*256+2; i < 7*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 7
    DFA[7*256].state = 1;
    DFA[7*256].transition = 'D';
    DFA[7*256+1].state = 9;
    DFA[7*256+1].transition = 'A';
    DFA[7*256+2].state = 8;
    DFA[7*256+2].transition = 0;
    //for(int i = 7*256+3; i < 8*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 8
    DFA[8*256].state = 1;
    DFA[8*256].transition = 'D';
    DFA[8*256+1].state = 9;
    DFA[8*256+1].transition = 'A';
    //for(int i = 8*256+2; i < 9*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //state 9
    DFA[9*256].state = 9;
    DFA[9*256].transition = 0;
    //for(int i = 9*256+1; i < 10*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    //rest of space 
    //for(int i = 10*256; i < 256*256; i++){DFA[i].state = 0; DFA[i].transition = 0;}
    
    return 0;
}

int initDFA(){ //initialize or reset DFA and ORAM
    int ret = 0;
    //printf("HI!!\n");
    //printf("MAX_STATES %d\n", MAX_STATES);
    accepting = 0;
    memset(posMap, 0, MAX_STATES*4);
    memset(ORAM, 0, MAX_STATES*sizeof(Oram_Bucket));
    //memset(LinScan, 0, MAX_STATES*sizeof(Oram_Block));
    memset(stash, 0, STASH_SPACE*sizeof(Oram_Block));
    state = 0;
    
    //init oram
    for(int i = 0; i < MAX_STATES; i++){
        for(int j = 0; j < BUCKET_SIZE; j++) {
            ORAM[i].blocks[j].actualAddr = -1; //-1 means dummy block
        }
        
        ret += sgx_read_rand((uint8_t*)&posMap[i], sizeof(unsigned int));
        posMap[i] = posMap[i] % (MAX_STATES/2+1);
        //printf("posmapi %d\n", posMap[i]);
    }

        //set stash empty
    for(int i = 0; i < 2*STASH_SPACE; i++){
        stash[i].actualAddr = -1;
    }
    
    //read in DFA row by row and put in ORAM
    for(int i = 0; i < MAX_STATES; i++){
        block.actualAddr = i;
        memcpy(&(block.transitions), &DFA[i*256], 256*sizeof(Entry));
        //printf("oram results: %d %d %d %c\n", block.actualAddr, block.transitions[1].state, block.leaf, block.transitions[1].transition);
        opOram(i, &block, 1);
    }

    
    return ret;
}

int opOram(int index, Oram_Block* block, int write){ //the actual oram ops
    unsigned int newLeaf, targetLeaf = 0;
    int match = 0;
    sgx_read_rand((uint8_t*)&newLeaf, sizeof(unsigned int));
    newLeaf = newLeaf % (MAX_STATES/2+1);
    //printf("starting oram op");
    //linear scan over position map to select leaf where index lives and to replace it with new leaf
    for(int i = 0; i < MAX_STATES; i++){
        match = (index == i);
        targetLeaf += match*posMap[i];//printf("targetLeaf %d\n", targetLeaf);
        posMap[i] = match*newLeaf + (1-match)*posMap[i];
        //if(match) printf("matched leaf, updating posMap to %d\n", posMap[i]);
    }
    //printf("target leaf: %d, new leaf: %d\n", targetLeaf, newLeaf);
    //read in a path down the tree
    int nodeNumber = MAX_STATES/2+targetLeaf;
    int stashIndex = 0;
    for(int i = (int)log2(MAX_STATES+1.1)-1; i>=0; i--){//bucket at depth i on path to leaf
        for(int j = 0; j < BUCKET_SIZE; j++){//for each block in bucket
            //put block in stash, clear it from ORAM
            memcpy(&stash[stashIndex], &ORAM[nodeNumber].blocks[j], sizeof(Oram_Block));
            stashIndex++;
            ORAM[nodeNumber].blocks[j].actualAddr = -1;//empty spot where the block was before
        }
        nodeNumber = (nodeNumber-1)/2;
    }
    
      /*  printf("DEBUG: stash entries: ");
    for(int i = 0; i < 150; i++){
        printf(" (%d, %d,%c) ", stash[i].actualAddr, stash[i].transitions[0].state, stash[i].transitions[0].transition);
        
    }printf("\n");*/
    
    //sort entire stash of size 2*STASH_SPACE so we can ignore second half
    sortStash(0,2*STASH_SPACE, 0);
    
    //scan stash for block to return
    //NOTE: only handling reads, see below for writes
    //  and explanation. This would have to be changed for 
    //  full, general ORAM
    int foundItFlag = 0;
    stashIndex = 0;
    memset(&row, 0, sizeof(Oram_Block));
    for(int i = 0; i < STASH_SPACE; i++){
        stashIndex += (stash[i].actualAddr != -1); //add one to count of things in stash if this is a real block
        //printf("%d ", stashIndex);
        //put this block in variable row if it is meant to be returned
        match = (stash[i].actualAddr == index);
                //if(match) printf("MATCH");//printf("MATCH %d %d %d |", row.actualAddr,((uint8_t*)&row)[0], ((uint8_t*)(&stash[i]))[0] );

        stash[i].leaf = match*newLeaf + (1-match)*stash[i].leaf;
        for(int j = 0; j < sizeof(Oram_Block); j++){
            ((uint8_t*)&row)[j] += (match * ((uint8_t*)(&stash[i]))[j]);
        }
    }
    
    //handle case where the block is not found
    //ok to leak this branch, it will only happen during writes
    //and writes will only happen while loading in the DFA
    //and it will happen once to a new node for each entry
    //NOTE: a general solution would have to hide this branch
    //and also handle what happens if there's a read to a 
    //block that has not been touched before (I only handle the case for writes here)
    if(foundItFlag == 0 && write){
        memcpy(&stash[stashIndex], block, sizeof(Oram_Block));
        stash[stashIndex].actualAddr = index; //may be redundant
        stash[stashIndex].leaf = newLeaf;
        stashIndex++;
        //printf("inserted at stash index %d\n", stashIndex);
    }
    else{
        memcpy(block, &row, sizeof(Oram_Block));
    }
    
    /*printf("DEBUG: stash entries: ");
    for(int i = 0; i < stashIndex; i++){
        printf(" (%d, %d,%c) ", stash[i].actualAddr, stash[i].transitions[0].state, stash[i].transitions[0].transition);
        
    }printf("\n");*/
    
    //write back path
    nodeNumber = MAX_STATES/2+targetLeaf;
    for(int i = (int)log2(MAX_STATES+1.1)-1; i>=0; i--){
        int div = pow((double)2, ((int)log2(MAX_STATES+1.1)-1)-i);
        for(int j = 0; j < BUCKET_SIZE; j++){
            for(int k = 0; k < STASH_SPACE; k++){
                int conditionsMet = (ORAM[nodeNumber].blocks[j].actualAddr == -1) && (stash[k].actualAddr != -1) && (((MAX_STATES/2)+targetLeaf-(div-1))/div == ((MAX_STATES/2)+stash[k].leaf-(div-1))/div);
                //if(conditionsMet)printf("CONDITIONSMET = %d\n", conditionsMet);
                //if conditionsMet, write stash block to oram and remove from stash
                //write to oram
                for(int l = 0; l < sizeof(Oram_Block); l++){
                    uint8_t v1 = ((uint8_t*)(&ORAM[nodeNumber].blocks[j]))[l];
                    uint8_t v2 = ((uint8_t*)(&stash[k]))[l];
                    ((uint8_t*)(&ORAM[nodeNumber].blocks[j]))[l] = (!conditionsMet*v1)+(conditionsMet*v2);
                }                
                //remove from stash
                stash[k].actualAddr = (conditionsMet*-1)+(!conditionsMet*stash[k].actualAddr);
            }
        }
        nodeNumber = (nodeNumber-1)/2;
    }
    //move first half of stash to second half of stash
    memmove(&stash[STASH_SPACE], stash, STASH_SPACE*sizeof(Oram_Block));
    memset(stash, 0xff, STASH_SPACE*sizeof(Oram_Block));
}

void sortStash(int startIndex, int size, int flipped){//bitonic sort stash so all non -1 values appear before all -1 values
    if(size <= 1) return; //ok to leak this branch, attacker knows we're in sorting network
    else{
        sortStash(startIndex, size/2, 1);
        sortStash(startIndex+(size/2), size/2, 0);
        mergeStash(startIndex, size, flipped);   
    }
}

void mergeStash(int startIndex, int size, int flipped){//bitonic merge
    if(size == 1) return; //ok to leak this branch, attacker knows we're in sorting network
    else{
        int swap = 0;
        int half = size/2;
        for(int i = 0; i < half; i++){
            //only swap if there is a dummy block (-1) that needs to be moved to the end
            swap = ((stash[startIndex+i].actualAddr == -1) != flipped); //&& stash[startIndex+half+i].actualAddr != -1);
            //if(!swap) printf("NOTSWAP: %d\n", stash[startIndex+i].actualAddr);
            //compare and swap stash[startIndex+i] and stash[startIndex+i+half]
            memcpy(&row, &stash[startIndex+i], sizeof(Oram_Block));//use row as temp storage
            memcpy(&stash[startIndex+i], &stash[startIndex+i+half], sizeof(Oram_Block));
            for(int j = 0; j < sizeof(Oram_Block); j++){
                uint8_t v1 = ((uint8_t*)&row)[j];
                uint8_t v2 = ((uint8_t*)&(stash[startIndex+half+i]))[j];
                ((uint8_t*)(&stash[startIndex+i]))[j] = (!swap * v1) + (swap * v2);
                ((uint8_t*)(&stash[startIndex+half+i]))[j] = (swap * v1) + (!swap * v2);
            }
        }
        mergeStash(startIndex, size/2, flipped);
        mergeStash(startIndex+(size/2), size/2, flipped);
    }
}


int opDFA(char input){ //return >0 if accepting state, 0 otherwise
        int change = 0, changed = 0;
        int oldAcc = accepting;
        accepting = 0;
        opOram(state, &block, 0);
                //printf("oram results: %d %d %d %c\n", block.actualAddr, block.transitions[0].state, block.leaf, block.transitions[0].transition);

        for(int i = 0; i < 256; i++){
            changed = change || changed;
            change = (input == block.transitions[i].transition);
            change = change || (block.transitions[i].transition == 0 && !changed);
            state = state*(1-change) + (change)*block.transitions[i].state;
            //printf("change: %d, state: %d\n", change, state);
        }
        
        for(int i = 0; i < MAX_STATES; i++){
            accepting = (accepting || (state == i && accStates[i]));
        }
        //accepting *= state;
        //printf("DEBUG: input %c got us in state %d. Accepting? %d.\n", input, state, accepting);
        return accepting;
}

int runDFA(char* data, int length){
    int ret = -1, accLoc = -1;
    for(int i = 0; i < length; i++){
        ret = opDFA(data[i]);
        accLoc = (accLoc != -1 || !ret)*accLoc + (accLoc == -1 && ret)*i;
        //printf("accLoc %d\n", accLoc);
        //accepts as long as it accepted at any point, not if the whole DFA accepts
        //because we're doing more of a string search thing here
    }
    return accLoc;
}
