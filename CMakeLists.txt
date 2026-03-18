cmake_minimum_required(VERSION 3.14)
project(fuzzer VERSION 1.0 LANGUAGES CXX)

set(SRC_FILES
  FuzzerCrossOver.cpp
  FuzzerDataFlowTrace.cpp
  FuzzerDriver.cpp
  FuzzerExtFunctionsDlsym.cpp
  FuzzerExtFunctionsWeak.cpp
  FuzzerExtFunctionsWindows.cpp
  FuzzerExtraCounters.cpp
  FuzzerExtraCountersDarwin.cpp
  FuzzerExtraCountersWindows.cpp
  FuzzerFork.cpp
  FuzzerIO.cpp
  FuzzerIOPosix.cpp
  FuzzerIOWindows.cpp
  FuzzerLoop.cpp
  FuzzerMerge.cpp
  FuzzerMutate.cpp
  FuzzerSHA1.cpp
  FuzzerTracePC.cpp
  FuzzerUtil.cpp
  FuzzerUtilDarwin.cpp
  FuzzerUtilFuchsia.cpp
  FuzzerUtilLinux.cpp
  FuzzerUtilPosix.cpp
  FuzzerUtilWindows.cpp
  FuzzerInterceptors.cpp
  FuzzerMain.cpp
  FuzzerHFC.cpp
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# # 添加编译选项
# if(MSVC)
#   add_compile_options(/W4 /WX /D_HAS_EXCEPTIONS=0)
# else()
#   add_compile_options(-Wall -Wextra -Werror -fno-omit-frame-pointer)
#   # 检查thread_local支持
#   include(CheckCXXSourceCompiles)
#   CHECK_CXX_SOURCE_COMPILES(
#     "static thread_local int blah; int main() { return 0; }"
#     HAS_THREAD_LOCAL
#   )
#   if(NOT HAS_THREAD_LOCAL)
#     add_compile_definitions(thread_local=__thread)
#   endif()
# endif()

add_definitions(-DCPPHTTPLIB_NO_EXCEPTIONS)

# 包含第三方库目录
include_directories(third-party/cpp-httplib)
include_directories(third-party/json/include)

# 明确指定库类型
add_library(${PROJECT_NAME} STATIC ${SRC_FILES})

# 设置目标属性
target_include_directories(${PROJECT_NAME}
  PUBLIC
  ${PROJECT_SOURCE_DIR}
)

# # 设置库版本
# export(TARGETS ${PROJECT_NAME} FILE hfcTargets.cmake)
# install(TARGETS ${PROJECT_NAME} EXPORT hfcTargets
#   ARCHIVE DESTINATION lib
#   LIBRARY DESTINATION lib
#   RUNTIME DESTINATION bin
# )
# install(EXPORT hfcTargets DESTINATION lib/cmake/hfc)