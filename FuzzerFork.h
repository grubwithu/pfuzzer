//===- FuzzerFork.h - run fuzzing in sub-processes --------------*- C++ -* ===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_FUZZER_FORK_H
#define LLVM_FUZZER_FORK_H

#include "FuzzerDefs.h"
#include "FuzzerOptions.h"
#include "FuzzerRandom.h"
#include "FuzzerIO.h"
#include "FuzzerTracePC.h"
#include "FuzzerUtil.h"
#include "FuzzerInternal.h"
#include "FuzzerCommand.h"
#include <string>
#include <algorithm>
#include <vector>
#include <numeric>
#include <random>
#include <unordered_set>
#include <string>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <queue>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

namespace fuzzer {
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
    if (Line.find("stat::") != 0) continue;
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

struct FuzzerInfo{
    std::string Name;       // Fuzzer的名称
    size_t Selections = 0;  // 选择次数
    double Score = 0;       // 得分
    double UsedBudget = 0;  // 已使用预算
    size_t CoveredBranches = 0; // 覆盖分支数

    static std::vector<FuzzerInfo>::iterator FindByName(
        std::vector<FuzzerInfo>& fuzzerStatuses, const std::string& fuzzerName) {
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
    //bool NeedsEnergyUpdate = false;
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
  std::string JobBudget;
  std::string CorpusDir;
  std::string FeaturesDir;
  std::string LogPath;
  std::string InputDir;
  std::string SeedListPath;
  std::string CFPath;
  size_t      JobId;
  std::string StopFile;
  //int         DftTimeInSeconds = 0;
  std::vector<uint32_t> NewCov;
  std::vector<uintptr_t> NewFuncs;

  // Fuzzing Outputs.
  int ExitCode;

  ~FuzzJob() {
    RemoveFile(CFPath);
    // RemoveFile(LogPath);
    RemoveFile(SeedListPath);
    // RmDirRecursive(CorpusDir);
    RmDirRecursive(FeaturesDir);
  }
};

double CalculateJobFeedback(FuzzJob *Job, std::vector<MergeSeedInfo> &MergeSeedCandidates, TracePC::CoverageInfo &GlobalIt);
void SortMergeSeedCandidates(std::vector<MergeSeedInfo> &MergeSeedCandidates);
std::vector<std::string> ParseFuzzers(const char *fuzzers);
void CopyMultipleFiles(const std::vector<SeedInfo *> &JobSeeds, const std::string &InputDir);
std::string GetExeDirName();
std::string GetBaseName(const std::string &path);
std::string GetLocalCorpusDir(const std::string &CorpusDir, const std::string &FuzzerName);
std::string GetFuzzerName(std::vector<FuzzerInfo> &FuzzerStatuses, size_t JobId, std::string LogPath);

class ArgsInfo{
private:
    std::string CurrentPath;
    std::string Target_Program;
    std::unordered_map<std::string, std::vector<std::string>> AllFuzzersArgs;

public:
    ArgsInfo(const std::string &CurrentPath, const std::string &Target_Program){
        this->CurrentPath = CurrentPath;
        this->Target_Program = Target_Program;
        // 在构造函数中初始化AllFuzzersArgs
        AllFuzzersArgs = {
            {"afl", {CurrentPath + "/afl/afl-fuzz", "-m", "none", "-t", "1000+", "-d", "--"}},
            {"aflgo", {CurrentPath + "/aflgo/afl-fuzz", "-m", "none",  "-z", "exp", "-c", "45m", "-t", "1000+"}},
            {"aflplusplus", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+",  "-L", "-1", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
            {"symcc", {CurrentPath + "/symcc/afl-fuzz", "-p", "explore", "-t", "1000+",  "-L", "-1", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
            {"redqueen", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "1AT"}},
            {"lafintel", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-l", "2AT"}},
            {"mopt", {CurrentPath + "/aflplusplus/afl-fuzz", "-p", "explore", "-t", "1000+", "-L", "0", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
            {"radamsa", {CurrentPath + "/radamsa/afl-fuzz", "-p", "explore", "-t", "1000+", "-L", "-1", "-c", CurrentPath + "/aflplusplus/cmplog/" + Target_Program, "-l", "2AT"}},
            {"aflsmart", {CurrentPath + "/aflsmart/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
            {"darwin", {CurrentPath + "/darwin/afl-fuzz", "-m", "none",  "-t", "1000+"}},
            {"moptbk", {CurrentPath + "/mopt/afl-fuzz", "-m", "none", "-d", "-t", "1000+", "-L", "0"}},
            {"ecofuzz", {CurrentPath + "/ecofuzz/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
            {"fafuzz", {CurrentPath + "/fafuzz/afl-fuzz", "-m", "none", "-t", "1000+", "-d"}},
            {"fairfuzz", {CurrentPath + "/fairfuzz/afl-fuzz", "-m", "none", "-d", "-t", "1000+",}},
            {"aflfast", {CurrentPath + "/aflfast/afl-fuzz", "-m", "none", "-d", "-t", "1000+"}},
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
            {"eclipser", {"dotnet", CurrentPath + "/eclipser/Eclipser/build/Eclipser.dll", "--arg foo -f foo --noforkserver", "--exectimeout 10000", "-v 2 "}}
        };
    }

    void GetFuzzerCmd(const std::string &FuzzerName, FuzzJob &FuzzJob, std::vector<std::string> &Args, const std::vector<std::string> &CorpusDirs, std::string TempDir){
         std::vector<std::string> InitArgs;
        if (FuzzerName == "libfuzzer" || FuzzerName == "entropic" || FuzzerName == "wingfuzz"){
            InitArgs = Args;
            if (FuzzerName == "wingfuzz"){
                std::string TargetPath = DirPlusFile(CurrentPath, DirPlusFile(FuzzJob.FuzzerName, Target_Program));
                InitArgs[0] = TargetPath;
            }
            if (FuzzerName == "libfuzzer") {
                std::string TargetPath = DirPlusFile(CurrentPath, "ftfuzzer");
                InitArgs[0] = TargetPath;
            }
            Command Cmd(InitArgs);
            Cmd.removeFlag("fork");
            Cmd.removeFlag("runs");
            for (auto &C : CorpusDirs) // Remove all corpora from the args.
              Cmd.removeArgument(C);
            Cmd.addFlag("reload", "0");  // working in an isolated dir, no reload.
            Cmd.addFlag("print_final_stats", "1");
            Cmd.addFlag("verbosity", "2");
            //Cmd.addFlag("verbosity", "0");
            Cmd.addFlag("print_funcs", "0"); // no need to spend time symbolizing.
            Cmd.addFlag("max_total_time", FuzzJob.JobBudget);
            Cmd.addFlag("stop_file", FuzzJob.StopFile);
            if (FuzzerName == "entropic") Cmd.addFlag("entropic", "1");            
            std::string Seeds;
            for (auto &Seed : FuzzJob.JobSeeds){
                Seeds += (Seeds.empty() ? "" : ",") + Seed->FilePath;
            }
            if (!Seeds.empty()){
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
            //if (FuzzerName == "wingfuzz") Cmd.addFlag("wingfuzz", "1");
        }
        else {
            InitArgs = AllFuzzersArgs[FuzzerName];
            std::string TargetPath = DirPlusFile(CurrentPath, DirPlusFile(FuzzJob.FuzzerName, Target_Program));
            //在参数列表中的第一个参数，里面带有afl-fuzz字符串的命令，都需要添加下面参数" -i FuzzJob.InputDir -o FuzzJob.CorpusDir，位置在afl-fuzz后面"
            if (InitArgs[0].find("afl-fuzz") != std::string::npos){
                InitArgs.insert(InitArgs.begin() + 1, "-i");
                InitArgs.insert(InitArgs.begin() + 2, FuzzJob.InputDir);
                InitArgs.insert(InitArgs.begin() + 3, "-o");
                InitArgs.insert(InitArgs.begin() + 4, FuzzJob.CorpusDir);
                printf("fuzz name: %s\n", FuzzerName.c_str());
                if ((FuzzerName != "aflfast") && (FuzzerName != "aflgo")){
                    InitArgs.insert(InitArgs.begin() + 5, "-V");
                    InitArgs.insert(InitArgs.begin() + 6, FuzzJob.JobBudget);
                }

                //最后一个参数，输入binary路径 
                InitArgs.push_back(TargetPath);
                InitArgs.push_back("2147483647");
            }
            //在参数列表中的第一个参数，里面带有honggfuzz字符串的命令, 需要添加以下参数：-f FuzzJob.InputDir -W FuzzJob.CorpusDir"
            if (InitArgs[0].find("honggfuzz") != std::string::npos){
                InitArgs.insert(InitArgs.begin() + 1, "-f");
                InitArgs.insert(InitArgs.begin() + 2, FuzzJob.InputDir);
                InitArgs.insert(InitArgs.begin() + 3, "-W");
                InitArgs.insert(InitArgs.begin() + 4, FuzzJob.CorpusDir);
                InitArgs.insert(InitArgs.begin() + 5, "--run_time");
                InitArgs.insert(InitArgs.begin() + 6, FuzzJob.JobBudget);
                //最后一个参数，输入binary路径 
                InitArgs.push_back(TargetPath);
            }
            if (InitArgs[0].find("ankou") != std::string::npos){
                InitArgs.insert(InitArgs.begin() + 1, "-i");
                InitArgs.insert(InitArgs.begin() + 2, FuzzJob.InputDir);
                InitArgs.insert(InitArgs.begin() + 3, "-o");
                InitArgs.insert(InitArgs.begin() + 4, FuzzJob.CorpusDir);
                InitArgs.insert(InitArgs.begin() + 5, "-dur");
                InitArgs.insert(InitArgs.begin() + 6, FuzzJob.JobBudget);
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
        if (GlobalFeatureFreqs[Idx32] == 0xFFFF) return;
        uint16_t Freq = GlobalFeatureFreqs[Idx32]++;
        if (Freq == 1) NonZeroFeatures.push_back(Idx32);
    }
    void DeleteFile(const SeedInfo &SI) {
        RemoveFile(DirPlusFile(OutputCorpus, SI.File));
    }
    void DeleteInput(size_t Idx) {
        SeedInfo &SI = *Inputs[Idx];
        DeleteFile(SI);
        SI.Live = false;
        SI.Energy = 0.0;
        //SI.NeedsEnergyUpdate = false;
        //DistributionNeedsUpdate = true;
        SI.UCB1Score = 0;
        SI.SeedFuncs.clear();
        SI.SeedPCs.clear();
    }
    bool AddFeature(size_t Idx, uint32_t NewSize, std::set<uint32_t>* Features) {
        assert(NewSize);
        Idx = Idx % kFeatureSetSize;
        uint32_t OldSize = GetFeature(Idx);
        if (OldSize == 0 || OldSize > NewSize) {
        if (OldSize > 0) {
            size_t OldIdx = SmallestElementPerFeature[Idx];
            SeedInfo &SI = *Inputs[OldIdx];
            assert(SI.NumFeatures > 0);
            SI.NumFeatures--;
            if (SI.NumFeatures == 0){
            DeleteInput(OldIdx);
            DeleteNums++;
            }
        } else {
            NumAddedFeatures++;//Total new Features of The Corpus.
            Features->insert(Idx);
        }
        NumUpdatedFeatures++;// new features + small size cover this feature
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
        //UnLockedInputs.push_back(&SI);
        SI.File = File;
        SI.FilePath = FilePath;
        //SIZE  SIZE
        SI.NumFeatures = NumFeatures;
        SI.SeedFuncs = SeedFuncs;
        SI.SeedPCs = SeedPCs;
        //SI.SeedRarePCs = SeedRarePCs;
        SI.Live = true;
        //SI.Locked = false;
        SI.TimeOfUnit = TimeOfUnit;
        SI.Energy = 1;
        //SI.UniqFeatureSet = FeatureSet;
        return &SI;
    }

    size_t GetLiveInputsSize () const {return Inputs.size() - DeleteNums;} 
     //计算种子权重
    void CalculateSeedWeight(std::vector<TracePC::FuncInfo> &ValueFuncsList,
                            std::vector<TracePC::CoverageInfo> &CoverageInfos, std::string FuzzerName) {
        std::cout << "\tCalculating: Seed Weight for Fuzzer: " << FuzzerName << std::endl;
        double SeedWeight = 0;
        auto It = TracePC::CoverageInfo::FindByName(CoverageInfos, FuzzerName);
        if (It == CoverageInfos.end()) {
            //std::cout << "No value functions for this fuzzer found." << std::endl;
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
                //std::cout << "Function ID: " << Func.Id << " Weight: " << FuncWeight << std::endl;
            }
        }
        for (auto SI : Inputs) {
            size_t FuncCount = 0;
            double SeedWeight = 0;
            if (SI->Live) {
                for (const auto &Func : SI->SeedFuncs) {
                    std::string FileStr = DescribePC("%s", Func);
                    if (!IsInterestingCoverageFile(FileStr)) continue;
                    SeedWeight += FuncsWeightMap[Func];
                    FuncCount++;
                }
                //if (FuncCount > 0) SeedWeight /= FuncCount;
                SI->Energy = SeedWeight;
                //std::cout << "Seed: " << SI->File << " Weight: " << SeedWeight << " Function Count: " << FuncCount << std::endl;
            }
        }
    }
    // 根据种子选择次数和种子权重计算种子得分
    void CalculateSeedScore(double Explore) {
        //std::cout << "Calculating Seed Scores with Explore factor: " << Explore << std::endl;
        size_t TotalSelections = 0;
        for (auto SI : Inputs) {
            if (SI->Live) TotalSelections += SI->Selections;
        }
        for (auto SI : Inputs) {
            if (SI->Live) {
                if (SI->Selections > 3)
                    SI->UCB1Score = SI->Energy + Explore * sqrt(2 * log(TotalSelections) / SI->Selections);
                else
                    SI->UCB1Score = SI->Energy * (5 - SI->Selections);
                //std::cout << "UCB1 Score for " << SI->File << ": " << SI->UCB1Score << std::endl;
                //std::cout << "Selections for " << SI->File << ": " << SI->Selections << std::endl;
                //std::cout << "Energy for " << SI->File << ": " << SI->Energy << std::endl;
            }
        }
    }
    std::vector<SeedInfo *> GetJobSeeds(size_t SeedsNum, const std::string &FuzzerName, Random &Rand,
                                        std::vector<TracePC::CoverageInfo> &CoverageInfos, double Explore) {
        //std::cout << "Getting Job Seeds for Fuzzer: " << FuzzerName << " with Seed Number: " << SeedsNum << std::endl;
        std::vector<SeedInfo *> SortedSeeds;
        std::vector<SeedInfo *> JobSeeds;
        std::vector<TracePC::FuncInfo> ValueFuncsList = TPC.GetValueFuncsList(CoverageInfos, FuzzerName);
        //std::cout << "Value Functions List Size: " << ValueFuncsList.size() << std::endl;
        CalculateSeedWeight(ValueFuncsList, CoverageInfos, FuzzerName);
        CalculateSeedScore(Explore);
        //std::cout << "Calculated Seed Scores with Explore factor: " << Explore << std::endl;
        for (auto SI : Inputs) {
            if (SI->Live) SortedSeeds.push_back(SI);
        }
        //std::cout << "Number of Live Seeds: " << SortedSeeds.size() << std::endl;
        std::sort(SortedSeeds.begin(), SortedSeeds.end(), [](SeedInfo *a, SeedInfo *b) {
            return a->UCB1Score < b->UCB1Score;
        });
        size_t loop_count = 0;
        while (JobSeeds.size() < SeedsNum) {
            loop_count++;
            if (loop_count > 3 * SortedSeeds.size()) break;
            if (SortedSeeds.empty()) break;
            size_t Index = Rand.SkewTowardsLast(SortedSeeds.size());
            if (SortedSeeds[Index]->Locked) continue;
            SortedSeeds[Index]->Selections++;
            SortedSeeds[Index]->Locked = true;
            JobSeeds.push_back(SortedSeeds[Index]);
            //std::cout << "Selected Seed: " << SortedSeeds[Index]->File << " with UCB1 Score: " << SortedSeeds[Index]->UCB1Score << std::endl;
        }
        if (JobSeeds.size() <= 1) {
            std::cout << "No enough seeds selected, using random live seeds." << std::endl;
            for (size_t i = 0; i < SeedsNum; i++) {
                size_t Index = Rand.SkewTowardsLast(SortedSeeds.size());
                SortedSeeds[Index]->Selections++;
                SortedSeeds[Index]->Locked = true;
                JobSeeds.push_back(SortedSeeds[Index]);
            }
        }
        //std::cout << "Total Job Seeds Selected: " << JobSeeds.size() << std::endl;
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
