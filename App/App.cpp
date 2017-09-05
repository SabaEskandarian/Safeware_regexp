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


#include <stdio.h>
#include <string.h>
#include <assert.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <time.h>
//#include "../Enclave/Enclave.h"

//these definitions are for the baseline. To change the real settings, see Enclave.h
#define MAX_STATES 15 //size of block in terms of entries
#define BUCKET_SIZE 4
#define STASH_SPACE 128 //should be something like 90+4*log_2(MAX_STATES) for 2^-80 prob of failure on each access, but make it a power of 2

typedef struct{
    char transition;
    int state;
} Entry;

typedef struct{
	int actualAddr;
	Entry transitions[256];//possibility of a different transition for each symbol
	unsigned int leaf; //we have each block keep track of its leaf to avoid a bunch of linear scans of the posMap
} Oram_Block;

Entry DFA[MAX_STATES*256] = {0};
int accStates[MAX_STATES];
int accepting; //0 means no, any positive number means yes and it started at the index of that number
int state;
Oram_Block block; //use this outside opOram


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
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

int opDFABaseline(char input){ //return >0 if accepting state, 0 otherwise
        int change = 0, changed = 0;
        int oldAcc = accepting;
        accepting = 0;
        //opOram(state, &block, 0);
        //linear scan
        memset(&block, 0, sizeof(Oram_Block));
        memcpy(&(block.transitions[0]), (uint8_t*)&DFA[state*256], 256*sizeof(Entry));
        printf("fdfd %d %d", block.transitions[0].transition, input);
       
        for(int i = 0; i < 256; i++){
            if(input == block.transitions[i].transition || (block.transitions[i].transition == 0 && !changed)){
                changed = 1;
                state = block.transitions[i].state;
            }
        }       

        accepting = accStates[state];
        printf("DEBUG: input %c got us in state %d. Accepting? %d.\n", input, state, accepting);
        return accepting;
}

int runDFABaseline(char* data, int length){
    int ret = -1, accLoc = -1;
    for(int i = 0; i < length; i++){
        ret = opDFABaseline(data[i]);
        accLoc = (accLoc != -1 || !ret)*accLoc + (accLoc == -1 && ret)*i;
        //accepts as long as it accepted at any point, not if the whole DFA accepts
        //because we're doing more of a string search thing here
    }
    return accLoc;
}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        //printf("Enter a character before exit ...\n");
        //getchar();
        return -1; 
    }
    
    char* s1 = "This is a DARn long string containing DAfRgPA in the middle. Will it be recognized?";
    int l1 = strlen(s1);
    char* s2 = "jtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsPAlkffffd;fsh OL hflkdf dsoi";//100 bytes
    int l2 = strlen(s2);
    char* s3 = "jtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DARlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoi";//1000 bytes
    int l3 = strlen(s3);
    char* s4 = "jtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtD*ARP_Aj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh DLLlPAkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoijtkl; dkfj kdl hfds f'ashjoi cio JIKIFJk joidf;'sdj fkdy so kdfjlsfDAdRsAlkffffd;fsh OL hflkdff dsoi";//10,000 bytes
    int l4 = strlen(s4);
    
    int status;
    int acceptLoc = -1;
    printf("preparing automata\n");
    //prepDFA(global_eid, &status);
    prepDFA();

    
    //printf("initializing automata\n");
    //initDFA(global_eid, &status);
    
    printf("running automata\n");
    time_t startTime, endTime;
	double elapsedTime;
    startTime = clock();
    //runDFA(global_eid, &acceptLoc, s2, l2);
    acceptLoc = runDFABaseline(s2, l2);
    endTime = clock();
	elapsedTime = (double)(endTime - startTime)/(CLOCKS_PER_SEC);
    printf("running time: %.5fs\n", elapsedTime);
    if(acceptLoc == -1){
        printf("did not match\n");
    }
    else{
        printf("match found! accepted at position %d\n", acceptLoc);
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    return 0;
}

