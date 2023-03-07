# External Functions Auto-completion tool

this tool is an External Functions Auto-completion tool. External functions are those functions that are dynamically linked and referenced from header files. (such as libc, libstdc++)

to use this tool ,you have to make sure the gcc version on your platform is larger than the targeting elf file(you'd better install the latest gcc on your computer).

  The image below shows the overall architecture of the tool.

![Image text](https://github.com/Stephen-lei/anvill/blob/master/tools/ExternalFunctionAuto-Completion/framework.png)


# Dependencies
to use this tool,you have to install :

| Name                                                       | Version |
| ---------------------------------------------------------- | ------- |
| [jsoncpp](https://github.com/open-source-parsers/jsoncpp)                                | Latest  |
| [llvm](https://github.com/llvm/llvm-project)                                | 11.0+   |
| [Clang](http://clang.llvm.org/)                            | 11.0+   |
| [pyelftools](https://github.com/eliben/pyelftools)           | Latest  |


## How to use 
1.put the EFAT.py under the pyelftools dir,the file structure must be the same with the template below.


    |-- ExternalFunctionAuto-Completion
        |-- DemanglingTools/
            |--jsoncpp(clone from github and build)
            |--llvm(builed llvm library in you computer,you have to copy it from /usr/lib/llvm-**/include/llvm)
            |--test.cpp
        |-- dict/
        |-- pyelftools(clone from github and build)/
            |--EFAT.py
            |--elftools
            |--...
        |-- test/
        |-- Result/
        |-- README.md
        |-- generate_glibc_dict.py



2.set environment 'LIFT_GCC_LIB_PATH' to point to the "dict" dir
    
    
    export LIFT_GCC_LIB_PATH="(path).../dict" 

3.type command:
    
    
    python EFAT.py -complement ../test/X86/MotivatingExample 

4.the outputfile will generated in the 'Result' directory




## Detailed introduction of other parts
The project also has two sub-components, namely the C++ Demangling sub-module and the dict supplementary sub-module. The following describes how to use them respectively.

## C++ Demangling sub-module 
this sub-module is written by c++,and based on [jsoncpp](https://github.com/open-source-parsers/jsoncpp) and llvm/Demangle.h. To build the tools, you have to make sure the structure above.


to regenerate the Demanglingtools,try:

    clang++ -g   test.cpp -o Demanglingtools    (path to your llvm)/lib/libLLVMDemangle.a (path)/jsoncpp/build/debug/lib/libjsoncpp.a

## Dict supplementary sub-module 
This submodule is mainly responsible for parsing an AST tree containing header files of external libraries, and parsing function definitions (such as return values and parameters, etc.) from it. This information can assist the implementation of automation tools.

to regenerate the dict library,try:

    export CLANG_EXE="/usr/lib/llvm-11/bin/clang" (point to your clang)

    export CLANG_LIB="/usr/lib/llvm-11/lib/libclang-**.so.1" (point to your libclang.so)
    
    python generate_glibc_dict.py  
    --type c 
    --input ./dict/libc.h 
    --output ./dict/allcdict.py
            
