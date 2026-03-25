#!/bin/sh
# LIBFUZZER_SRC_DIR=$(dirname $0)
# CXX="${CXX:-clang}"
# for f in $LIBFUZZER_SRC_DIR/*.cpp; do
#   $CXX -g -O2 -fno-omit-frame-pointer  -stdlib=libc++ -std=c++11 $f -c &
 
# done
# wait
# rm -f libFuzzer.a
# ar r libFuzzer.a Fuzzer*.o
# rm -f Fuzzer*.o

export CC=clang
export CXX=clang++

mkdir -p build
rm -rf build/*
cd build

cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 ..
make -j12

