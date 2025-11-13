#!/bin/sh
LIBFUZZER_SRC_DIR=$(dirname $0)

(for f in *.cpp; do \
      clang-18 -stdlib=libc++ -fPIC -O2 -std=c++11 $f -c & \
    done && wait)
 ar r /usr/lib/libHCFUZZER.a Fuzzer*.o
 rm -f Fuzzer*.o