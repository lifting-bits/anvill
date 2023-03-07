# 脚本总体架构

脚本的总体架构设计见文档https://sole2021.feishu.cn/docx/ZujgdHixuodnsvxw8jLccm0unWc?from=from_copylink

## 各脚本详细介绍
generate_abi_wrapper.py 是mcsema项目自带的生成补充函数的脚本，这边进行复用并进行了大幅度的修改(修改部分都有中文注释)。
使用方法为：
 
首先配置环境变量：

    export CLANG_EXE="/usr/lib/llvm-11/bin/clang" 指向编译器所在文件夹
    export CLANG_LIB="/usr/lib/llvm-11/lib/libclang-11.so.1" 指向libclang-11.so.1
然后输入：

 
    python generate_abi_wrapper.py

    --arch amd64

    --type c/cpp 

    --input  ABI_libc.h (包含待补充库函数的头文件)

    --output ABI_ctype_11_28.c (解析出的补充函数结果文件)


pyelftools下的readelf_back.py 是解析elf文件中的name mangling函数并生成补充函数的脚本。该脚本复用了python_readelf工具解析elf文件的大部分框架，主要以新添加一个执行选项来实现(修改部分都有中文注释)。使用方法为:

    python readelf_back.py 

    -complement test(待翻译的elf文件)
            
输出一个test.txt， 里面包含解析出的name mangling函数的补充。