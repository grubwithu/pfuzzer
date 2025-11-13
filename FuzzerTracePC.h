//===- FuzzerTracePC.h - Internal header for the Fuzzer ---------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// fuzzer::TracePC
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_TRACE_PC
#define LLVM_FUZZER_TRACE_PC

#include "FuzzerDefs.h"
#include "FuzzerDictionary.h"
#include "FuzzerValueBitMap.h"

#include <set>
#include <unordered_map>
#include <cmath>
#include <iostream>

namespace fuzzer {

// TableOfRecentCompares (TORC) remembers the most recently performed
// comparisons of type T.
// We record the arguments of CMP instructions in this table unconditionally
// because it seems cheaper this way than to compute some expensive
// conditions inside __sanitizer_cov_trace_cmp*.
// After the unit has been executed we may decide to use the contents of
// this table to populate a Dictionary.
template<class T, size_t kSizeT>
struct TableOfRecentCompares {
  static const size_t kSize = kSizeT;
  struct Pair {
    T A, B;
  };
  ATTRIBUTE_NO_SANITIZE_ALL
  void Insert(size_t Idx, const T &Arg1, const T &Arg2) {
    Idx = Idx % kSize;
    Table[Idx].A = Arg1;
    Table[Idx].B = Arg2;
  }

  Pair Get(size_t I) { return Table[I % kSize]; }

  Pair Table[kSize];
};

template <size_t kSizeT>
struct MemMemTable {
  static const size_t kSize = kSizeT;
  Word MemMemWords[kSize];
  Word EmptyWord;

  void Add(const uint8_t *Data, size_t Size) {
    if (Size <= 2) return;
    Size = std::min(Size, Word::GetMaxSize());
    auto Idx = SimpleFastHash(Data, Size) % kSize;
    MemMemWords[Idx].Set(Data, Size);
  }
  const Word &Get(size_t Idx) {
    for (size_t i = 0; i < kSize; i++) {
      const Word &W = MemMemWords[(Idx + i) % kSize];
      if (W.size()) return W;
    }
    EmptyWord.Set(nullptr, 0);
    return EmptyWord;
  }
};



class TracePC {
 public:

  struct PCTableEntry {
    uintptr_t PC, PCFlags;
  };

  struct FuncInfo {
    uintptr_t Id;
    size_t Hits = 0;
    size_t UncoverSize = 0;
    size_t CoveredSize = 0;
    //size_t NoNewCount = 2;
    //double Weight;
    FuncInfo(uintptr_t id, size_t hits, size_t uncoverSize, size_t coveredSize/*, size_t noNewCount*/)
      : Id(id), Hits(hits), UncoverSize(uncoverSize), CoveredSize(coveredSize)/*, NoNewCount(noNewCount)*/ {}

    double GetWeight(size_t GlobalAverageHits) const {
      if (Hits <= 0)
        return 0;
      double sqrtHits = sqrt(Hits);
      double RelativeFrequency = (GlobalAverageHits > 0) ? (sqrtHits / GlobalAverageHits) : 0;
      //double HighFrequencyThreshold = GlobalAverageHits;
      double LowFrequencyThreshold = GlobalAverageHits * 0.5;
      //if (sqrtHits > HighFrequencyThreshold) return 0;
      if (UncoverSize > 0) {
        double FrequencyPenalty = 1 / (1 + log(1 + RelativeFrequency));
        if (sqrtHits > LowFrequencyThreshold) return 4 * UncoverSize * FrequencyPenalty;
        else return 40 * UncoverSize * FrequencyPenalty;
      }
      return 2;
    }

    bool operator==(const FuncInfo &other) const {
        return Id == other.Id;
    }
  };

  struct CoverageInfo {
    std::string FuzzerName;
    std::set<const PCTableEntry *> ObservedPCs;
    std::unordered_map<uintptr_t, uintptr_t> ObservedFuncs;  // PC => Counter.
    std::unordered_map<uintptr_t, uintptr_t> LastObservedFuncs;  // PC => Counter.
    std::vector<FuncInfo> FuncsInfo;
    size_t FuncsAverageHits;

    static std::vector<CoverageInfo>::iterator FindByName(
        std::vector<CoverageInfo>& CoverageInfos, const std::string& fuzzerName) {
        return std::find_if(CoverageInfos.begin(), CoverageInfos.end(),
                            [&fuzzerName](const CoverageInfo &info) {
                                return info.FuzzerName == fuzzerName;
                            });
    }
  };

  size_t CalculateFuncsAverageHits(std::vector<CoverageInfo> &CoverageInfos, std::string FuzzerName) {
    std::cout << "\tCalculating: Functions Average Hits for Fuzzer: " << FuzzerName << std::endl;
    auto It = CoverageInfo::FindByName(CoverageInfos, FuzzerName);
    //如果这里没找到对应FuzzerName的CoverageInfo，则返回第一个CoverageInfo的FuncsInfo的平均值，即global average hits
    if (It == CoverageInfos.end()) {
        //std::cout << "Fuzzer not found in CoverageInfos." << std::endl;
        It = CoverageInfos.begin();
    }
    if (It->FuncsInfo.empty()) {
        //std::cout << "No function info available for Fuzzer: " << FuzzerName << std::endl;
        return 0;
    }
    size_t TotalHits = 0;
    size_t FuncCount = 0;
    for (const auto &Func : It->FuncsInfo) {
        if (Func.Hits > 0) {
            TotalHits += sqrt(Func.Hits);
            FuncCount++;
        }
    }
    std::cout << "\tCalculating:Total Hits: " << TotalHits << " Function Count: " << FuncCount << std::endl;
    return FuncCount > 0 ? TotalHits / FuncCount : 0;
  }
  //低频函数识别 
  std::vector<FuncInfo> GetValueFuncsList(std::vector<CoverageInfo> &CoverageInfos, std::string FuzzerName) {
    //std::cout << "Getting Value Functions List for Fuzzer: " << FuzzerName << std::endl;
    std::vector<FuncInfo> ValueFuncsList;
    //std::vector<FuncInfo> HighFrequencyFuncsList;
    auto GlobalAverageHits = CalculateFuncsAverageHits(CoverageInfos, FuzzerName);
    //std::cout << "Global Average Hits: " << GlobalAverageHits << std::endl;
    auto It = CoverageInfo::FindByName(CoverageInfos, FuzzerName);
    if (It == CoverageInfos.end()) {
        //std::cout << "No value functions for this fuzzer found 1." << std::endl;
        It = CoverageInfos.begin();
    }
    It->FuncsAverageHits = GlobalAverageHits;
    for (const auto &Func : It->FuncsInfo) {
        if (Func.Hits > 0) {
            if (sqrt(Func.Hits) <= GlobalAverageHits) {
                ValueFuncsList.push_back(Func);
                //std::cout << "Added Function ID: " << Func.Id << " with Hits: " << Func.Hits << std::endl;
            }
        }
    }

    if (It == CoverageInfos.end()) {
      //std::cout << "Total Value Functions: " << ValueFuncsList.size() << std::endl;
      return ValueFuncsList;
    } 

    for (const auto &Func : CoverageInfos[0].FuncsInfo) {
        if (std::find(It->FuncsInfo.begin(), It->FuncsInfo.end(), Func) == It->FuncsInfo.end()) {
            FuncInfo NewFunc = Func;
            NewFunc.Hits = 0;
            NewFunc.UncoverSize = Func.UncoverSize + Func.CoveredSize;
            NewFunc.CoveredSize = 0;
            ValueFuncsList.push_back(NewFunc);
            //std::cout << "Added New Function ID: " << NewFunc.Id << " as uncovered." << std::endl;
        }
    }
    //std::cout << "Total Value Functions: " << ValueFuncsList.size() << std::endl;
    return ValueFuncsList;
  }

  void HandleInline8bitCountersInit(uint8_t *Start, uint8_t *Stop);
  void HandlePCsInit(const uintptr_t *Start, const uintptr_t *Stop);
  void HandleCallerCallee(uintptr_t Caller, uintptr_t Callee);
  template <class T> void HandleCmp(uintptr_t PC, T Arg1, T Arg2);
  size_t GetTotalPCCoverage(CoverageInfo &CI);
  size_t GetTotalPCCoverage();
  void SetUseCounters(bool UC) { UseCounters = UC; }
  void SetUseValueProfileMask(uint32_t VPMask) { UseValueProfileMask = VPMask; }
  void SetPrintNewPCs(bool P) { DoPrintNewPCs = P; }
  void SetPrintNewFuncs(size_t P) { NumPrintNewFuncs = P; }
  void UpdateObservedPCs(CoverageInfo &CI);
  void UpdateObservedPCs();
  void GetSeedTrace();
  template <class Callback> size_t CollectFeatures(Callback CB) const;

  void ResetMaps() {
    ValueProfileMap.Reset();
    ClearExtraCounters();
    ClearInlineCounters();
  }

  void ClearInlineCounters();

  void UpdateFeatureSet(size_t CurrentElementIdx, size_t CurrentElementSize);
  void PrintFeatureSet();

  void PrintModuleInfo();

  void PrintCoverage(bool PrintAllCounters, CoverageInfo &CI);
  void PrintCoverage(bool PrintAllCounters);

  template<class CallBack>
  void IterateCoveredFunctions(CallBack CB, CoverageInfo &CI);
  template<class CallBack>
  void IterateCoveredFunctions(CallBack CB);

  void AddValueForMemcmp(void *caller_pc, const void *s1, const void *s2,
                         size_t n, bool StopAtZero);

  TableOfRecentCompares<uint32_t, 32> TORC4;
  TableOfRecentCompares<uint64_t, 32> TORC8;
  TableOfRecentCompares<Word, 32> TORCW;
  MemMemTable<1024> MMT;

  void RecordInitialStack();
  uintptr_t GetMaxStackOffset() const;

  template<class CallBack>
  void ForEachObservedPC(CallBack CB, CoverageInfo &CI) {
    for (auto PC : CI.ObservedPCs)
      CB(PC);
  }
  template<class CallBack>
  void ForEachObservedPC(CallBack CB) {
    for (auto PC : ObservedPCs)
      CB(PC);
  }

  template<class CallBack>
  void ForEachCurrentObservedPC(CallBack CB) {
    for (auto PC : CurrentObservedPCs)
      CB(PC);
  }

  void SetFocusFunction(const std::string &FuncName);
  bool ObservedFocusFunction();
  size_t ObservedFocusFunctions();


  

  uintptr_t PCTableEntryIdx(const PCTableEntry *TE);
  const PCTableEntry *PCTableEntryByIdx(uintptr_t Idx);
  static uintptr_t GetNextInstructionPc(uintptr_t PC);
  bool PcIsFuncEntry(const PCTableEntry *TE) { return TE->PCFlags & 1; }
  void GetFuncFreqsUncoveredInfo(CoverageInfo &CI);
  //bool FuncsInfoUpdate = false;
  
  
  
private:
  bool UseCounters = false;
  uint32_t UseValueProfileMask = false;
  bool DoPrintNewPCs = false;
  size_t NumPrintNewFuncs = 0;

  // Module represents the array of 8-bit counters split into regions
  // such that every region, except maybe the first and the last one, is one
  // full page.
  struct Module {
    struct Region {
      uint8_t *Start, *Stop;
      bool Enabled;
      bool OneFullPage;
    };
    Region *Regions;
    size_t NumRegions;
    uint8_t *Start() { return Regions[0].Start; }
    uint8_t *Stop()  { return Regions[NumRegions - 1].Stop; }
    size_t Size()   { return Stop() - Start(); }
    size_t  Idx(uint8_t *P) {
      assert(P >= Start() && P < Stop());
      return P - Start();
    }
  };

  Module Modules[4096];
  size_t NumModules;  // linker-initialized.
  size_t NumInline8bitCounters;

  template <class Callback>
  void IterateCounterRegions(Callback CB) {
    for (size_t m = 0; m < NumModules; m++)
      for (size_t r = 0; r < Modules[m].NumRegions; r++)
        CB(Modules[m].Regions[r]);
  }

  struct { const PCTableEntry *Start, *Stop; } ModulePCTable[4096];
  size_t NumPCTables;
  size_t NumPCsInPCTables;

  std::set<const PCTableEntry *> ObservedPCs;
  std::unordered_map<uintptr_t, uintptr_t> ObservedFuncs;  // PC => Counter.
  std::vector<const PCTableEntry *> CurrentObservedPCs;
  //std::unordered_map<uintptr_t, uintptr_t> LastObservedFuncs;  // PC => Counter.

  

  uint8_t *FocusFunctionCounterPtr = nullptr;
  std::vector<uint8_t *> FocusFunctionsCounterPtr; 

  ValueBitMap ValueProfileMap;
  uintptr_t InitialStack;
};

template <class Callback>
// void Callback(size_t FirstFeature, size_t Idx, uint8_t Value);
ATTRIBUTE_NO_SANITIZE_ALL
size_t ForEachNonZeroByte(const uint8_t *Begin, const uint8_t *End,
                        size_t FirstFeature, Callback Handle8bitCounter) {
  typedef uintptr_t LargeType;
  const size_t Step = sizeof(LargeType) / sizeof(uint8_t);
  const size_t StepMask = Step - 1;
  auto P = Begin;
  // Iterate by 1 byte until either the alignment boundary or the end.
  for (; reinterpret_cast<uintptr_t>(P) & StepMask && P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature, P - Begin, V);

  // Iterate by Step bytes at a time.
  for (; P + Step <= End; P += Step)
    if (LargeType Bundle = *reinterpret_cast<const LargeType *>(P)) {
      Bundle = HostToLE(Bundle);
      for (size_t I = 0; I < Step; I++, Bundle >>= 8)
        if (uint8_t V = Bundle & 0xff)
          Handle8bitCounter(FirstFeature, P - Begin + I, V);
    }

  // Iterate by 1 byte until the end.
  for (; P < End; P++)
    if (uint8_t V = *P)
      Handle8bitCounter(FirstFeature, P - Begin, V);
  return End - Begin;
}

// Given a non-zero Counter returns a number in the range [0,7].
template<class T>
unsigned CounterToFeature(T Counter) {
    // Returns a feature number by placing Counters into buckets as illustrated
    // below.
    //
    // Counter bucket: [1] [2] [3] [4-7] [8-15] [16-31] [32-127] [128+]
    // Feature number:  0   1   2    3     4       5       6       7
    //
    // This is a heuristic taken from AFL (see
    // http://lcamtuf.coredump.cx/afl/technical_details.txt).
    //
    // This implementation may change in the future so clients should
    // not rely on it.
    assert(Counter);
    unsigned Bit = 0;
    /**/ if (Counter >= 128) Bit = 7;
    else if (Counter >= 32) Bit = 6;
    else if (Counter >= 16) Bit = 5;
    else if (Counter >= 8) Bit = 4;
    else if (Counter >= 4) Bit = 3;
    else if (Counter >= 3) Bit = 2;
    else if (Counter >= 2) Bit = 1;
    return Bit;
}

template <class Callback> // void Callback(uint32_t Feature)
ATTRIBUTE_NO_SANITIZE_ADDRESS ATTRIBUTE_NOINLINE size_t
TracePC::CollectFeatures(Callback HandleFeature) const {
  auto Handle8bitCounter = [&](size_t FirstFeature,
                               size_t Idx, uint8_t Counter) {
    if (UseCounters)
      HandleFeature(static_cast<uint32_t>(FirstFeature + Idx * 8 +
                                          CounterToFeature(Counter)));
    else
      HandleFeature(static_cast<uint32_t>(FirstFeature + Idx));
  };

  size_t FirstFeature = 0;

  for (size_t i = 0; i < NumModules; i++) {
    for (size_t r = 0; r < Modules[i].NumRegions; r++) {
      if (!Modules[i].Regions[r].Enabled) continue;
      FirstFeature += 8 * ForEachNonZeroByte(Modules[i].Regions[r].Start,
                                             Modules[i].Regions[r].Stop,
                                             FirstFeature, Handle8bitCounter);
    }
  }

  FirstFeature +=
      8 * ForEachNonZeroByte(ExtraCountersBegin(), ExtraCountersEnd(),
                             FirstFeature, Handle8bitCounter);

  if (UseValueProfileMask) {
    ValueProfileMap.ForEach([&](size_t Idx) {
      HandleFeature(static_cast<uint32_t>(FirstFeature + Idx));
    });
    FirstFeature += ValueProfileMap.SizeInBits();
  }

  // Step function, grows similar to 8 * Log_2(A).
  auto StackDepthStepFunction = [](size_t A) -> size_t {
    if (!A)
      return A;
    auto Log2 = Log(A);
    if (Log2 < 3)
      return A;
    Log2 -= 3;
    return (Log2 + 1) * 8 + ((A >> Log2) & 7);
  };
  assert(StackDepthStepFunction(1024) == 64);
  assert(StackDepthStepFunction(1024 * 4) == 80);
  assert(StackDepthStepFunction(1024 * 1024) == 144);

  if (auto MaxStackOffset = GetMaxStackOffset()) {
    HandleFeature(static_cast<uint32_t>(
        FirstFeature + StackDepthStepFunction(MaxStackOffset / 8)));
    FirstFeature += StackDepthStepFunction(std::numeric_limits<size_t>::max());
  }

  return FirstFeature;
}

extern TracePC TPC;

}  // namespace fuzzer

#endif  // LLVM_FUZZER_TRACE_PC
