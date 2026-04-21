//===- FuzzerFork.h - run fuzzing in sub-processes --------------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_FORK_H
#define LLVM_FUZZER_FORK_H

#include "FuzzerCommand.h"
#include "FuzzerDefs.h"
#include "FuzzerIO.h"
#include "FuzzerInternal.h"
#include "FuzzerOptions.h"
#include "FuzzerRandom.h"
#include "FuzzerTracePC.h"
#include "FuzzerUtil.h"
#include <algorithm>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numeric>
#include <queue>
#include <random>
#include <stdio.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace fuzzer {

constexpr size_t SEED_STRATEGY_NEW = 0x1;
constexpr size_t SEED_STRATEGY_UCB1 = 0x2;
constexpr size_t SEED_STRATEGY_CORPUS = 0x4;

constexpr size_t FUZZER_STRATEGY_RANDOM = 0x1;
constexpr size_t FUZZER_STRATEGY_UCB1 = 0x2;
constexpr size_t FUZZER_STRATEGY_CORPUS = 0x4;

void FuzzWithFork(Random &Rand, const FuzzingOptions &Options,
                  const std::vector<std::string> &Args,
                  const std::vector<std::string> &CorpusDirs,
                  int NumJobs, UserCallback Callback,
                  std::vector<std::string> Fuzzers);

struct Stats {
  size_t number_of_executed_units = 0;
  size_t peak_rss_mb = 0;
  size_t average_exec_per_sec = 0;
};

static Stats ParseFinalStatsFromLog(const std::string &LogPath) {
  std::ifstream In(LogPath);
  std::string Line;
  Stats Res;
  struct {
    const char *Name;
    size_t *Var;
  } NameVarPairs[] = {
      {"stat::number_of_executed_units:", &Res.number_of_executed_units},
      {"stat::peak_rss_mb:", &Res.peak_rss_mb},
      {"stat::average_exec_per_sec:", &Res.average_exec_per_sec},
      {nullptr, nullptr},
  };
  while (std::getline(In, Line, '\n')) {
    if (Line.find("stat::") != 0)
      continue;
    std::istringstream ISS(Line);
    std::string Name;
    size_t Val;
    ISS >> Name >> Val;
    for (size_t i = 0; NameVarPairs[i].Name; i++)
      if (Name == NameVarPairs[i].Name)
        *NameVarPairs[i].Var = Val;
  }
  return Res;
}

struct FuzzerInfo {
  std::string Name;           // Fuzzer的名称
  size_t Selections = 0;      // 选择次数
  double Score = 0;           // 得分
  double UsedBudget = 0;      // 已使用预算
  size_t CoveredBranches = 0; // 覆盖分支数

  static std::vector<FuzzerInfo>::iterator FindByName(
      std::vector<FuzzerInfo> &fuzzerStatuses, const std::string &fuzzerName) {
    return std::find_if(fuzzerStatuses.begin(), fuzzerStatuses.end(),
                        [&fuzzerName](const FuzzerInfo &info) {
                          return info.Name == fuzzerName;
                        });
  }
};

struct SeedInfo {
  std::string File;
  std::string FilePath;
  size_t Size;
  std::chrono::microseconds TimeOfUnit;
  std::vector<uintptr_t> SeedFuncs;
  std::vector<const TracePC::PCTableEntry *> SeedPCs;
  size_t NumFeatures = 0; // 每个种子独占的特征数量，被减至0时，该种子被删除。
  bool Live = true;
  bool Locked = false;
  size_t Selections = 0;
  double Energy = 0.0;
  // bool NeedsEnergyUpdate = false;
  double UCB1Score = 0;
};

struct MergeSeedInfo {
  std::string FilePath;
  size_t Size = 0;
  std::vector<uint32_t> Features;
  std::vector<uintptr_t> SeedFuncs;
  std::vector<const TracePC::PCTableEntry *> SeedPCs;
  std::chrono::microseconds TimeOfUnit;
  double SortedWeight = 0;
};

struct FuzzJob {
  // Inputs.
  Command Cmd;
  std::string FuzzerName;
  std::vector<SeedInfo *> JobSeeds;
  std::string BinaryName;
  size_t JobBudget;
  std::string CorpusDir;
  std::string FeaturesDir;
  std::string LogPath;
  std::string InputDir;
  std::string SeedListPath;
  std::string CFPath;
  size_t JobId;
  std::string StopFile;
  std::string DictPath;
  // int         DftTimeInSeconds = 0;
  std::vector<uint32_t> NewCov;
  std::vector<uintptr_t> NewFuncs;

  // Fuzzing Outputs.
  int ExitCode;

  inline std::string JobBudgetStr() {
    return std::to_string(JobBudget);
  }

  ~FuzzJob() {
    RemoveFile(CFPath);
    // RemoveFile(LogPath);
    RemoveFile(SeedListPath);
    RmDirRecursive(CorpusDir);
    RmDirRecursive(FeaturesDir);
    RemoveFile(DictPath);
  }
};

double CalculateJobFeedback(FuzzJob *Job, std::vector<MergeSeedInfo> &MergeSeedCandidates, TracePC::CoverageInfo &GlobalIt);
void SortMergeSeedCandidates(std::vector<MergeSeedInfo> &MergeSeedCandidates);
std::vector<std::string> ParseFuzzers(const char *fuzzers);
void CopyMultipleFiles(const std::vector<SeedInfo *> &JobSeeds, const std::string &InputDir);
std::string GetExeDirName();
std::string GetBaseName(const std::string &path);
std::string GetLocalCorpusDir(const std::string &CorpusDir, const std::string &FuzzerName);
std::string GetFuzzerNameUCB1(std::vector<FuzzerInfo> &FuzzerStatuses, size_t JobId, std::string LogPath);
std::string GetFuzzerNameRound(std::vector<FuzzerInfo> &FuzzerStatuses);

class ArgsInfo {
private:
  std::string CurrentPath;
  std::string Target_Program;
  std::unordered_map<std::string, std::vector<std::string>> AllFuzzersArgs;

public:
  ArgsInfo(const std::string &CurrentPath, const std::string &Target_Program) {
    this->CurrentPath = CurrentPath;
    this->Target_Program = Target_Program;
    // 在构造函数中初始化AllFuzzersArgs
    AllFuzzersArgs = {
        {"afl", {CurrentPath + "/afl/afl-fuzz", "-m", "none", "-t", "1000+", "-d", "--"}},
        {"aflgo", {CurrentPath + "/aflgo/afl-fuzz", "-m", "none", "-z", "exp", "-c", "45m", "-t", "1000+"}},
        {"aflplusplus", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-L", "-1", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
        {"symcc", {CurrentPath + "/symcc/afl-fuzz", "-p", "explore", "-t", "1000+", "-L", "-1", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
        {"redqueen", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "1AT"}},
        {"lafintel", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-l", "2AT"}},
        // {"mopt", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-L", "0", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
        {"radamsa", {CurrentPath + "/radamsa/afl-fuzz", "-p", "explore", "-t", "1000+", "-L", "-1", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
        {"aflsmart", {CurrentPath + "/aflsmart/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
        {"darwin", {CurrentPath + "/darwin/afl-fuzz", "-m", "none", "-t", "1000+"}},
        {"mopt", {CurrentPath + "/mopt/afl-fuzz", "-m", "none", "-d", "-t", "1000+", "-L", "0"}},
        {"ecofuzz", {CurrentPath + "/ecofuzz/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
        {"fafuzz", {CurrentPath + "/fafuzz/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
        {"fairfuzz", {CurrentPath + "/fairfuzz/afl-fuzz", "-m", "none", "-d", "-t", "1000+"}},
        {"aflfast", {CurrentPath + "/aflfast/afl-fuzz", "-m", "none", "-t", "1000+", "-d", "--"}},
        {"qsym", {"python2", CurrentPath + "/qsym/bin/run_qsym_afl.py"}},
        {"hastefuzz", {CurrentPath + "/hastefuzz/afl-fuzz", "-p", "fast", "-L", "0", "-t", "1000+", "-x", CurrentPath + "/hastefuzz/afl++.dict", "-c", CurrentPath + "/hastefuzz/cmplog/" + Target_Program, "-l", "2", "-u", "0"}},
        {"honggfuzz", {CurrentPath + "/honggfuzz/honggfuzz", "--persistent", "--rlimit_rss", "2048", "--sanitizers_del_report=true", "--"}},
        {"learnperffuzz", {CurrentPath + "/learnperffuzz/afl-fuzz", "-m", "none", "-d"}},
        {"neuzz", {CurrentPath + "/neuzz/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
        {"libfuzzer", {""}},
        {"entropic", {"-entropic = 1"}},
        {"wingfuzz", {""}},
        {"weizz", {CurrentPath + "/weizz/weizz", "-m", "none", "-d", "-t", "1000+", "-F", "-c", "-A"}},
        {"ankou", {CurrentPath + "/ankou/ankou", "-args", "'@@'", "-select", "WMO", "-app"}},
        {"eclipser", {"dotnet", CurrentPath + "/eclipser/Eclipser/build/Eclipser.dll", "--arg foo -f foo --noforkserver", "--exectimeout 10000", "-v 2 "}}};
  }

  void GetFuzzerCmd(const std::string &FuzzerName, FuzzJob &FuzzJob, std::vector<std::string> &Args, const std::vector<std::string> &CorpusDirs, std::string TempDir, const std::string &DictPath) {
    std::vector<std::string> InitArgs;
    if (FuzzerName == "libfuzzer" || FuzzerName == "entropic" || FuzzerName == "wingfuzz") {
      InitArgs = Args;
      if (FuzzerName == "wingfuzz") {
        std::string TargetPath = DirPlusFile(CurrentPath, DirPlusFile(FuzzJob.FuzzerName, Target_Program));
        InitArgs[0] = TargetPath;
      }
      if (FuzzerName == "libfuzzer" || FuzzerName == "entropic") {
        std::string TargetPath = DirPlusFile(CurrentPath, Target_Program);
        InitArgs[0] = TargetPath;
      }
      Command Cmd(InitArgs);
      Cmd.removeFlag("fork");
      Cmd.removeFlag("runs");
      Cmd.removeFlag("entropic");
      for (auto &C : CorpusDirs) // Remove all corpora from the args.
        Cmd.removeArgument(C);
      Cmd.addFlag("reload", "0"); // working in an isolated dir, no reload.
      Cmd.addFlag("print_final_stats", "1");
      Cmd.addFlag("verbosity", "2");
      // Cmd.addFlag("verbosity", "0");
      Cmd.addFlag("print_funcs", "0"); // no need to spend time symbolizing.
      Cmd.addFlag("max_total_time", FuzzJob.JobBudgetStr());
      Cmd.addFlag("stop_file", FuzzJob.StopFile);
      if (!DictPath.empty()) {
        Cmd.addFlag("dict", DictPath);
      }
      if (FuzzerName == "entropic")
        Cmd.addFlag("entropic", "1");
      else
        Cmd.addFlag("entropic", "0");
      std::string Seeds;
      for (auto &Seed : FuzzJob.JobSeeds) {
        Seeds += (Seeds.empty() ? "" : ",") + Seed->FilePath;
      }
      if (!Seeds.empty()) {
        FuzzJob.SeedListPath = DirPlusFile(TempDir, std::to_string(FuzzJob.JobId) + ".seeds");
        WriteToFile(Seeds, FuzzJob.SeedListPath);
      }
      Cmd.addFlag("seed_inputs", "@" + FuzzJob.SeedListPath);
      std::string output = DirPlusFile(FuzzJob.CorpusDir, "output");
      std::string crash = DirPlusFile(FuzzJob.CorpusDir, "crash");
      std::string libfuzzer_log = DirPlusFile(FuzzJob.CorpusDir, "libfuzzer.log");
      MkDir(output);
      MkDir(crash);
      Cmd.addArgument(output);
      char path[100];
      sprintf(path, "-artifact_prefix=%s/", crash.c_str());
      std::string crash_arg(path);
      Cmd.addArgument(crash_arg);
      Cmd.addFlag("features_dir", FuzzJob.FeaturesDir);
      Cmd.setOutputFile(libfuzzer_log);
      Cmd.combineOutAndErr();
      FuzzJob.Cmd = Cmd;
      // if (FuzzerName == "wingfuzz") Cmd.addFlag("wingfuzz", "1");
    } else {
      if (AllFuzzersArgs.find(FuzzerName) == AllFuzzersArgs.end()) {
        Printf("Fatal Error: Fuzzer %s not found\n", FuzzerName.c_str());
        exit(1);
      }
      InitArgs = AllFuzzersArgs[FuzzerName];
      std::string TargetPath = DirPlusFile(CurrentPath, DirPlusFile(FuzzJob.FuzzerName, Target_Program));
      // 在参数列表中的第一个参数，里面带有afl-fuzz字符串的命令，都需要添加下面参数" -i FuzzJob.InputDir -o FuzzJob.CorpusDir，位置在afl-fuzz后面"
      if (InitArgs[0].find("afl-fuzz") != std::string::npos) {
        InitArgs.insert(InitArgs.begin() + 1, "-i");
        InitArgs.insert(InitArgs.begin() + 2, FuzzJob.InputDir);
        InitArgs.insert(InitArgs.begin() + 3, "-o");
        InitArgs.insert(InitArgs.begin() + 4, FuzzJob.CorpusDir);
        Printf("fuzzer name: %s\n", FuzzerName.c_str());
        // if ((FuzzerName != "aflfast") && (FuzzerName != "aflgo")) {
        InitArgs.insert(InitArgs.begin() + 5, "-V");
        InitArgs.insert(InitArgs.begin() + 6, FuzzJob.JobBudgetStr());
        // }
        if (!DictPath.empty()) {
          InitArgs.insert(InitArgs.begin() + 7, "-x");
          InitArgs.insert(InitArgs.begin() + 8, DictPath);
        }
        
        // 最后一个参数，输入binary路径
        InitArgs.push_back(TargetPath);
        InitArgs.push_back("2147483647");
      }
      // 在参数列表中的第一个参数，里面带有honggfuzz字符串的命令, 需要添加以下参数：-f FuzzJob.InputDir -W FuzzJob.CorpusDir"
      if (InitArgs[0].find("honggfuzz") != std::string::npos) {
        InitArgs.insert(InitArgs.begin() + 1, "-f");
        InitArgs.insert(InitArgs.begin() + 2, FuzzJob.InputDir);
        InitArgs.insert(InitArgs.begin() + 3, "-W");
        InitArgs.insert(InitArgs.begin() + 4, FuzzJob.CorpusDir);
        InitArgs.insert(InitArgs.begin() + 5, "--run_time");
        InitArgs.insert(InitArgs.begin() + 6, FuzzJob.JobBudgetStr());
        // 最后一个参数，输入binary路径
        InitArgs.push_back(TargetPath);
      }
      if (InitArgs[0].find("ankou") != std::string::npos) {
        InitArgs.insert(InitArgs.begin() + 1, "-i");
        InitArgs.insert(InitArgs.begin() + 2, FuzzJob.InputDir);
        InitArgs.insert(InitArgs.begin() + 3, "-o");
        InitArgs.insert(InitArgs.begin() + 4, FuzzJob.CorpusDir);
        InitArgs.insert(InitArgs.begin() + 5, "-dur");
        InitArgs.insert(InitArgs.begin() + 6, FuzzJob.JobBudgetStr());
        InitArgs.push_back(TargetPath);
      }
      Command Cmd(InitArgs);
      Cmd.setOutputFile(FuzzJob.LogPath);
      Cmd.combineOutAndErr();
      FuzzJob.Cmd = Cmd;
    }
  }
};

class GlobalCorpusInfo {
  static const uint32_t kFeatureSetSize = 1 << 21;

public:
  GlobalCorpusInfo(const std::string &OutputCorpus) : OutputCorpus(OutputCorpus) {
    memset(InputSizesPerFeature, 0, sizeof(InputSizesPerFeature));
    memset(SmallestElementPerFeature, 0, sizeof(SmallestElementPerFeature));
  }
  ~GlobalCorpusInfo() {
    for (auto SI : Inputs)
      delete SI;
  }
  size_t NumFeatureUpdates() const { return NumUpdatedFeatures; }
  size_t NumFeatures() const { return NumAddedFeatures; }

  void UpdateFeatureFrequency(SeedInfo *SI, size_t Idx) {
    uint32_t Idx32 = Idx % kFeatureSetSize;
    // Saturated increment.
    if (GlobalFeatureFreqs[Idx32] == 0xFFFF)
      return;
    uint16_t Freq = GlobalFeatureFreqs[Idx32]++;
    if (Freq == 1)
      NonZeroFeatures.push_back(Idx32);
  }
  void DeleteFile(const SeedInfo &SI) {
    RemoveFile(DirPlusFile(OutputCorpus, SI.File));
  }
  void DeleteInput(size_t Idx) {
    SeedInfo &SI = *Inputs[Idx];
    DeleteFile(SI);
    SI.Live = false;
    SI.Energy = 0.0;
    // SI.NeedsEnergyUpdate = false;
    // DistributionNeedsUpdate = true;
    SI.UCB1Score = 0;
    SI.SeedFuncs.clear();
    SI.SeedPCs.clear();
  }
  bool AddFeature(size_t Idx, uint32_t NewSize, std::set<uint32_t> *Features) {
    assert(NewSize);
    Idx = Idx % kFeatureSetSize;
    uint32_t OldSize = GetFeature(Idx);
    if (OldSize == 0 || OldSize > NewSize) {
      if (OldSize > 0) {
        size_t OldIdx = SmallestElementPerFeature[Idx];
        SeedInfo &SI = *Inputs[OldIdx];
        assert(SI.NumFeatures > 0);
        SI.NumFeatures--;
        if (SI.NumFeatures == 0) {
          DeleteInput(OldIdx);
          DeleteNums++;
        }
      } else {
        NumAddedFeatures++; // Total new Features of The Corpus.
        Features->insert(Idx);
      }
      NumUpdatedFeatures++; // new features + small size cover this feature
      // Inputs.size() is guaranteed to be less than UINT32_MAX by AddToCorpus.
      SmallestElementPerFeature[Idx] = static_cast<uint32_t>(Inputs.size());
      InputSizesPerFeature[Idx] = NewSize;
      return true;
    }
    return false;
  }
  SeedInfo *AddToCorpus(const std::string File, const std::string FilePath,
                        size_t NumFeatures, /*bool MayDeleteFile,
                        bool HasFocusFunction, bool NeverReduce,*/
                        std::chrono::microseconds TimeOfUnit,
                        const std::vector<uint32_t> &FeatureSet,
                        std::vector<const TracePC::PCTableEntry *> &SeedPCs,
                        std::vector<uintptr_t> &SeedFuncs
                        /*const DataFlowTrace &DFT, const SeedInfo *BaseSI*/) {
    // Inputs.size() is cast to uint32_t below.
    assert(Inputs.size() < std::numeric_limits<uint32_t>::max());
    Inputs.push_back(new SeedInfo());
    SeedInfo &SI = *Inputs.back();
    // UnLockedInputs.push_back(&SI);
    SI.File = File;
    SI.FilePath = FilePath;
    // SIZE  SIZE
    SI.NumFeatures = NumFeatures;
    SI.SeedFuncs = SeedFuncs;
    SI.SeedPCs = SeedPCs;
    // SI.SeedRarePCs = SeedRarePCs;
    SI.Live = true;
    // SI.Locked = false;
    SI.TimeOfUnit = TimeOfUnit;
    SI.Energy = 1;
    // SI.UniqFeatureSet = FeatureSet;
    return &SI;
  }

  size_t GetLiveInputsSize() const { return Inputs.size() - DeleteNums; }
  // 计算种子权重
  void CalculateSeedWeight(std::vector<TracePC::FuncInfo> &ValueFuncsList,
                           std::vector<TracePC::CoverageInfo> &CoverageInfos, std::string FuzzerName) {
    // std::cerr << "\tCalculating: Seed Weight for Fuzzer: " << FuzzerName << std::endl;
    Printf("\tCalculating: Seed Weight for Fuzzer: %s\n", FuzzerName.c_str());
    double SeedWeight = 0;
    auto It = TracePC::CoverageInfo::FindByName(CoverageInfos, FuzzerName);
    if (It == CoverageInfos.end()) {
      // std::cout << "No value functions for this fuzzer found." << std::endl;
      It = CoverageInfos.begin();
    }
    std::unordered_map<std::uintptr_t, double> FuncsWeightMap;
    if (!ValueFuncsList.empty()) {
      for (const auto &Func : ValueFuncsList) {
        double FuncWeight = Func.GetWeight(It->FuncsAverageHits);
        if (FuncWeight > 0) {
          FuncsWeightMap[Func.Id] = FuncWeight;
        } else {
          FuncsWeightMap[Func.Id] = 1000;
        }
        // std::cout << "Function ID: " << Func.Id << " Weight: " << FuncWeight << std::endl;
      }
    }
    for (auto SI : Inputs) {
      size_t FuncCount = 0;
      double SeedWeight = 0;
      if (SI->Live) {
        for (const auto &Func : SI->SeedFuncs) {
          std::string FileStr = DescribePC("%s", Func);
          if (!IsInterestingCoverageFile(FileStr))
            continue;
          SeedWeight += FuncsWeightMap[Func];
          FuncCount++;
        }
        // if (FuncCount > 0) SeedWeight /= FuncCount;
        SI->Energy = SeedWeight;
        // std::cout << "Seed: " << SI->File << " Weight: " << SeedWeight << " Function Count: " << FuncCount << std::endl;
      }
    }
  }
  // 基于 ConstraintGroup 计算种子能量。
  // 公式：Energy = 目标函数贡献 - 非目标函数惩罚
  // 权重：主函数(1000) | 路径函数(50~1000 靠近目标递增) | 非目标(1.0~GetWeight 用于惩罚)
  // 经过目标区域函数 → 增加能量；经过非目标函数 → 减少能量。
  void CalculateSeedWeight(ConstraintGroup &SelectedGroup,
                           std::vector<TracePC::CoverageInfo> &CoverageInfos,
                           std::string FuzzerName) {
    std::unordered_map<std::uintptr_t, double> TargetWeightMap;   // 目标函数(主+路径)，覆盖则加分
    std::unordered_map<std::uintptr_t, double> NonTargetWeightMap; // 非目标函数，覆盖则扣分
    if (CoverageInfos.empty())
      return;
    size_t GlobalAverageHits = TPC.CalculateFuncsAverageHits(CoverageInfos, FuzzerName);
    auto &FuncsInfo = CoverageInfos[0].FuncsInfo;
    const double kWeightBonusRatio = 0.15;
    const double kNonTargetWeightMin = 1.0; // 非目标函数最小权重（用于惩罚）
    const double kPathWeightMin = 50;
    const double kPathWeightMax = 1000;

    std::unordered_map<std::string, double> PathFuncBaseWeight;
    auto Path = SelectedGroup.Path;
    if (!Path.empty()) {
      for (size_t idx = 0; idx < Path.size(); idx++) {
        double w = kPathWeightMin + (kPathWeightMax - kPathWeightMin) *
                                        static_cast<double>(idx + 1) /
                                        Path.size();
        auto it = PathFuncBaseWeight.find(Path[idx]);
        if (it == PathFuncBaseWeight.end() || w > it->second)
          PathFuncBaseWeight[Path[idx]] = w;
      }
    }

    for (const auto &Func : FuncsInfo) {
      auto FuncName = DescribePC_Mangled(Func.Id);
      double baseWeight = 0;
      if (FuncName == SelectedGroup.LeafFunction) {
        baseWeight = 1000;
      } else {
        auto it = PathFuncBaseWeight.find(FuncName);
        if (it != PathFuncBaseWeight.end())
          baseWeight = it->second;
      }

      double funcBonus = Func.GetWeight(GlobalAverageHits);
      if (funcBonus <= 0)
        funcBonus = 0;

      if (baseWeight > 0) {
        double w = baseWeight + kWeightBonusRatio * funcBonus;
        TargetWeightMap[Func.Id] = w;
      } else {
        NonTargetWeightMap[Func.Id] = std::max(kNonTargetWeightMin, funcBonus);
      }
    }

    double maxEnergy = 0;
    double minEnergy = 1e9;
    size_t liveCount = 0;
    for (auto SI : Inputs) {
      if (!SI->Live)
        continue;
      liveCount++;
      double targetSum = 0;    // 经过目标函数 → 增加能量
      double nonTargetSum = 0; // 经过非目标函数 → 减少能量
      for (const auto &FuncId : SI->SeedFuncs) {
        std::string FileStr = DescribePC("%s", FuncId);
        if (!IsInterestingCoverageFile(FileStr))
          continue;
        auto itT = TargetWeightMap.find(FuncId);
        if (itT != TargetWeightMap.end()) {
          targetSum += itT->second;
        } else {
          auto itN = NonTargetWeightMap.find(FuncId);
          double w = (itN != NonTargetWeightMap.end()) ? itN->second : kNonTargetWeightMin;
          nonTargetSum += w;
        }
      }
      SI->Energy = std::max(0.0, targetSum - nonTargetSum);
      if (SI->Energy > maxEnergy)
        maxEnergy = SI->Energy;
      if (SI->Energy < minEnergy)
        minEnergy = SI->Energy;
    }

    // std::cerr << "\t[Constraint] main=" << SelectedGroup.LeafFunction << " targetFuncs=" << TargetWeightMap.size()
    //           << " nonTargetFuncs=" << NonTargetWeightMap.size() << " liveSeeds=" << liveCount;
    Printf("\t[Constraint] main=%s targetFuncs=%d nonTargetFuncs=%d liveSeeds=%d\n",
           SelectedGroup.LeafFunction.c_str(), TargetWeightMap.size(), NonTargetWeightMap.size(), liveCount);
    
    if (liveCount > 0) {
      Printf("EnergyRange=[%.2f, %.2f]\n", minEnergy, maxEnergy);
    }
  }
  // 根据种子选择次数和种子权重计算种子得分
  void CalculateSeedScore(double Explore) {
    // std::cout << "Calculating Seed Scores with Explore factor: " << Explore << std::endl;
    size_t TotalSelections = 0;
    for (auto SI : Inputs) {
      if (SI->Live)
        TotalSelections += SI->Selections;
    }
    for (auto SI : Inputs) {
      if (SI->Live) {
        if (SI->Selections > 3)
          SI->UCB1Score = SI->Energy + Explore * sqrt(2 * log(TotalSelections) / SI->Selections);
        else
          SI->UCB1Score = SI->Energy * (5 - SI->Selections);
        // std::cout << "UCB1 Score for " << SI->File << ": " << SI->UCB1Score << std::endl;
        // std::cout << "Selections for " << SI->File << ": " << SI->Selections << std::endl;
        // std::cout << "Energy for " << SI->File << ": " << SI->Energy << std::endl;
      }
    }
  }

  std::vector<SeedInfo *> GetJobSeedsConstraint(size_t SeedsNum, const std::string &FuzzerName, Random &Rand,
                                                std::vector<TracePC::CoverageInfo> &CoverageInfos, double Explore,
                                                ConstraintGroup &SelectedGroup) {
    // std::cout << "Getting Job Seeds for Fuzzer: " << FuzzerName << " with Seed Number: " << SeedsNum << std::endl;
    std::vector<SeedInfo *> SortedSeeds;
    std::vector<SeedInfo *> JobSeeds;

    CalculateSeedWeight(SelectedGroup, CoverageInfos, FuzzerName);
    CalculateSeedScore(Explore); // UCB1：平衡 Energy 与 Selections，多次选取的种子得分降低
    for (auto SI : Inputs) {
      if (SI->Live)
        SortedSeeds.push_back(SI);
    }
    std::sort(SortedSeeds.begin(), SortedSeeds.end(), [](SeedInfo *a, SeedInfo *b) {
      return a->UCB1Score > b->UCB1Score;
    });

    std::vector<SeedInfo *> Candidates;
    for (size_t i = 0; i < SortedSeeds.size() && Candidates.size() < 2 * SeedsNum; i++) {
      if (SortedSeeds[i]->Locked)
        continue;
      Candidates.push_back(SortedSeeds[i]);
    }

    std::sort(Candidates.begin(), Candidates.end(), [](SeedInfo *a, SeedInfo *b) {
      return a->TimeOfUnit.count() < b->TimeOfUnit.count();
    });
    for (size_t i = 0; i < Candidates.size() && JobSeeds.size() < SeedsNum; i++) {
      Candidates[i]->Selections++;
      Candidates[i]->Locked = true;
      JobSeeds.push_back(Candidates[i]);
    }
    if (JobSeeds.size() < SeedsNum && !SortedSeeds.empty()) {
      // std::cerr << "No enough constraint seeds, filling with SkewTowardsLast." << std::endl;
      Printf("No enough constraint seeds, filling with SkewTowardsLast.\n");
      size_t needed = SeedsNum - JobSeeds.size();
      size_t filled = 0;
      for (size_t retries = 0; filled < needed && retries < 3 * SortedSeeds.size(); retries++) {
        size_t Index = Rand.SkewTowardsLast(SortedSeeds.size());
        SeedInfo *seed = SortedSeeds[Index];
        if (seed->Locked)
          continue;
        seed->Selections++;
        seed->Locked = true;
        JobSeeds.push_back(seed);
        filled++;
      }
    }
    return JobSeeds;
  }

  std::vector<SeedInfo *> GetJobSeedsUCB1(size_t SeedsNum, const std::string &FuzzerName, Random &Rand,
                                          std::vector<TracePC::CoverageInfo> &CoverageInfos, double Explore) {
    std::vector<SeedInfo *> SortedSeeds;
    std::vector<SeedInfo *> JobSeeds;

    std::vector<TracePC::FuncInfo> ValueFuncsList = TPC.GetValueFuncsList(CoverageInfos, FuzzerName);
    CalculateSeedWeight(ValueFuncsList, CoverageInfos, FuzzerName);
    CalculateSeedScore(Explore);
    for (auto SI : Inputs) {
      if (SI->Live)
        SortedSeeds.push_back(SI);
    }
    std::sort(SortedSeeds.begin(), SortedSeeds.end(), [](SeedInfo *a, SeedInfo *b) {
      return a->UCB1Score < b->UCB1Score;
    });
    size_t loop_count = 0;
    while (JobSeeds.size() < SeedsNum) {
      loop_count++;
      if (loop_count > 3 * SortedSeeds.size())
        break;
      if (SortedSeeds.empty())
        break;
      size_t Index = Rand.SkewTowardsLast(SortedSeeds.size());
      if (SortedSeeds[Index]->Locked)
        continue;
      SortedSeeds[Index]->Selections++;
      SortedSeeds[Index]->Locked = true;
      JobSeeds.push_back(SortedSeeds[Index]);
    }
    if (JobSeeds.size() < SeedsNum && !SortedSeeds.empty()) {
      // std::cerr << "No enough UCB1 seeds selected, filling with SkewTowardsLast." << std::endl;
      Printf("No enough UCB1 seeds selected, filling with SkewTowardsLast.\n");
      size_t needed = SeedsNum - JobSeeds.size();
      for (size_t i = 0; i < needed; i++) {
        size_t Index = Rand.SkewTowardsLast(SortedSeeds.size());
        SeedInfo *seed = SortedSeeds[Index];
        seed->Selections++;
        seed->Locked = true;
        JobSeeds.push_back(seed);
      }
    }
    return JobSeeds;
  }

  std::vector<SeedInfo *> GetJobSeedsNew(size_t SeedsNum, const std::string &FuzzerName, Random &Rand,
                                         std::vector<TracePC::CoverageInfo> &CoverageInfos, double Explore) {
    (void)FuzzerName;
    (void)CoverageInfos;
    (void)Explore;
    std::vector<SeedInfo *> SortedSeeds;
    std::vector<SeedInfo *> JobSeeds;

    std::vector<std::pair<size_t, SeedInfo *>> IndexedSeeds;
    for (size_t i = 0; i < Inputs.size(); i++) {
      if (Inputs[i]->Live)
        IndexedSeeds.push_back({i, Inputs[i]});
    }
    std::sort(IndexedSeeds.begin(), IndexedSeeds.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });
    for (const auto &p : IndexedSeeds)
      SortedSeeds.push_back(p.second);

    size_t loop_count = 0;
    while (JobSeeds.size() < SeedsNum) {
      loop_count++;
      if (loop_count > 3 * SortedSeeds.size())
        break;
      if (SortedSeeds.empty())
        break;
      size_t Index = Rand.SkewTowardsLast(SortedSeeds.size()); // 偏向后半部分=更新
      if (SortedSeeds[Index]->Locked)
        continue;
      SortedSeeds[Index]->Selections++;
      SortedSeeds[Index]->Locked = true;
      JobSeeds.push_back(SortedSeeds[Index]);
    }
    if (JobSeeds.size() < SeedsNum && !SortedSeeds.empty()) {
      // std::cerr << "No enough newest seeds selected, filling with SkewTowardsLast." << std::endl;
      Printf("No enough newest seeds selected, filling with SkewTowardsLast.\n");
      size_t needed = SeedsNum - JobSeeds.size();
      for (size_t i = 0; i < needed; i++) {
        size_t Index = Rand.SkewTowardsLast(SortedSeeds.size());
        SeedInfo *seed = SortedSeeds[Index];
        seed->Selections++;
        seed->Locked = true;
        JobSeeds.push_back(seed);
      }
    }
    return JobSeeds;
  }

private:
  uint32_t GetFeature(size_t Idx) const { return InputSizesPerFeature[Idx]; }
  std::vector<SeedInfo *> Inputs;
  size_t DeleteNums = 0;
  uint32_t NumUpdatedFeatures = 0;
  size_t NumAddedFeatures = 0;
  uint32_t InputSizesPerFeature[kFeatureSetSize];
  uint32_t SmallestElementPerFeature[kFeatureSetSize];
  uint16_t GlobalFeatureFreqs[kFeatureSetSize] = {0};
  std::vector<uint32_t> NonZeroFeatures;
  std::string OutputCorpus;
};

} // namespace fuzzer
#endif // LLVM_FUZZER_FORK_H
