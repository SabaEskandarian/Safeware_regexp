Sample code to run a regex query for D.?A.?R.?P.?A
   
-Edit App/App.cpp to use one of strings s1-s4
-Edit Enclave/Enclave.h to set MAX_STATES, the maximum number of states 
 supported by the DFA evaluator and the size to which all DFAs will be obliviously padded

------------------------------------
How to Build/Execute the Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        $ make
    b. Hardware Mode, Pre-release build:
        $ make SGX_PRERELEASE=1 SGX_DEBUG=0
    c. Hardware Mode, Release build:
        $ make SGX_DEBUG=0
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    e. Simulation Mode, Pre-release build:
        $ make SGX_MODE=SIM SGX_PRERELEASE=1 SGX_DEBUG=0
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
3. Execute the binary directly:
    $ ./app
4. Remember to "make clean" before switching build mode

