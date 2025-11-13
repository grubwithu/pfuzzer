//===- FuzzerFork.cpp - run fuzzing in separate subprocesses --------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
// Spawn and orchestrate separate fuzzing processes.
//===----------------------------------------------------------------------===//

#include "FuzzerCommand.h"
#include "FuzzerFork.h"
#include "FuzzerIO.h"
#include "FuzzerInternal.h"
#include "FuzzerMerge.h"
#include "FuzzerSHA1.h"
#include "FuzzerTracePC.h"
#include "FuzzerUtil.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <fstream>
#include <memory>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>

namespace fuzzer {


struct GlobalEnv {
  std::vector<std::string> Args;
  std::vector<std::string> CorpusDirs;
  std::string MainCorpusDir;
  std::string TempDir;
  //std::string DFTDir;
  //std::string DataFlowBinary;
  std::set<uint32_t> Features, Cov;
  std::set<uintptr_t> Funcs;
  //std::set<std::string> FilesWithDFT;
  std::vector<std::string> Files;
  std::vector<std::size_t> FilesSizes;
  Random *Rand;
  std::chrono::system_clock::time_point ProcessStartTime;
  int Verbosity = 0;
  int Group = 0;
  int NumCorpuses = 8;

  size_t NumTimeouts = 0;
  size_t NumOOMs = 0;
  size_t NumCrashes = 0;

  size_t NumRuns = 0;
  
  UserCallback Callback;
  std::mutex Mtx;
  std::vector<std::string> Fuzzers;
  std::vector<FuzzerInfo> FuzzerStatuses;
  //输出一些信息到本地文本文件中
  std::string LogPath;

  std::string StopFile() { return DirPlusFile(TempDir, "STOP"); }

  size_t secondsSinceProcessStartUp() const {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now() - ProcessStartTime)
        .count();
  }

  FuzzJob *CreateNewJob(size_t JobId, GlobalCorpusInfo *GlobalCorpus, std::vector<TracePC::CoverageInfo> *CoverageInfos, ArgsInfo *AllArgsInfo) {
    //COV or Crash
    //Select a fuzzer
    //Select seeds
    //GetJobType
    auto Job = new FuzzJob;
    Job->JobId = JobId;
    //加锁
    std::string FuzzerName;
    {
      std::lock_guard<std::mutex> Lock(Mtx);
      FuzzerName = GetFuzzerName(FuzzerStatuses, JobId, LogPath);
      Job->FuzzerName = FuzzerName;
      auto it = FuzzerInfo::FindByName(FuzzerStatuses, FuzzerName);
      if (it != FuzzerStatuses.end()) it->Selections++;
    }
    std::string JobBudget = std::to_string(std::min((size_t)3600, JobId * 20));//TODO GetJobBudget FUNC()
    Job->JobBudget = JobBudget;
    size_t SeedsNum = std::min(GlobalCorpus->GetLiveInputsSize(), 10 * (size_t)sqrt(GlobalCorpus->GetLiveInputsSize() + 2));// TODO GetSeedsNum FUNC()
    //智能锁
    std::vector<SeedInfo *> JobSeeds;
    {
      std::lock_guard<std::mutex> Lock(Mtx);
      JobSeeds = GlobalCorpus->GetJobSeeds(SeedsNum, FuzzerName, *Rand, *CoverageInfos, 1.0);
    }
    Job->JobSeeds = JobSeeds;
    Job->LogPath = DirPlusFile(TempDir, std::to_string(JobId) + ".log");
    Job->CorpusDir = DirPlusFile(TempDir, "C" + std::to_string(JobId));
    Job->InputDir = DirPlusFile(TempDir, "I" + std::to_string(JobId));
    Job->FeaturesDir = DirPlusFile(TempDir, "F" + std::to_string(JobId));
    Job->CFPath = DirPlusFile(TempDir, std::to_string(JobId) + ".merge");
    Job->StopFile = StopFile();
    for (auto &D : {Job->CorpusDir, Job->FeaturesDir, Job->InputDir}) {
      RmDirRecursive(D);
      MkDir(D);
    }
    CopyMultipleFiles(JobSeeds, Job->InputDir);
    AllArgsInfo->GetFuzzerCmd(FuzzerName, *Job, Args, CorpusDirs, TempDir);
    //Print Job INFO :JobId Job->FuzzerName Jobseeds num , jobbudget JobInput JobcORPUS
    Printf("\tCreateNewJob Done: JobId: %zd, FuzzerName: %s, JobSeedsNum: %zd, JobBudget: %s, JobInput: %s, JobCorpus: %s\n",
           JobId, Job->FuzzerName.c_str(), JobSeeds.size(), Job->JobBudget.c_str(), Job->InputDir.c_str(), Job->CorpusDir.c_str());
    //将CreateNewJob信息写入LogPath
    std::ofstream LogFile(LogPath, std::ios::app);
    LogFile << "\tCreateNewJob Done: JobId: " << JobId << ", FuzzerName: " << Job->FuzzerName << ", JobSeedsNum: " << JobSeeds.size() << ", JobBudget: " << Job->JobBudget << ", JobInput: " << Job->InputDir << ", JobCorpus: " << Job->CorpusDir << std::endl;
    LogFile.close();
    if (Verbosity >= 2)
      Printf("Job %zd/%p Created: %s\n", JobId, Job,
             Job->Cmd.toString().c_str());
    // Start from very short runs and gradually increase them.
    return Job;
  }

  void RunOneMergeJob(FuzzJob *Job, std::vector<TracePC::CoverageInfo> *CoverageInfos, GlobalCorpusInfo *GlobalCorpus) {
    //TODO
    //1.Collect loacl corpus seeds
    //2.Run these seeds and collect coverage info
    //3.calculate the feedback of job and fuzzer
    //4.Merge coverage info
    //5.Update global corpus
    //加锁
    {
      std::lock_guard<std::mutex> Lock(Mtx);
      auto Stats = ParseFinalStatsFromLog(Job->LogPath);
      NumRuns += Stats.number_of_executed_units;
    }
    std::string LocalCorpusDir = GetLocalCorpusDir(Job->CorpusDir, Job->FuzzerName);
    std::vector<SizedFile> LocalCorpusSeeds;
    GetSizedFilesFromDir(LocalCorpusDir, &LocalCorpusSeeds);
    //std::sort(LocalCorpusSeeds.begin(), LocalCorpusSeeds.end());
    std::vector<MergeSeedInfo> MergeSeedCandidates;
    //找到std::vector<TracePC::CoverageInfo> *CoverageInfos中FuzzerName对应的CoverageInfo
    auto FuzzerIt = std::find_if(CoverageInfos->begin(), CoverageInfos->end(), [&](const TracePC::CoverageInfo &Info){ return Info.FuzzerName == Job->FuzzerName; });
    if (FuzzerIt == CoverageInfos->end()) {
      //std::cout << "No coverage info for this fuzzer found." << std::endl;
      FuzzerIt = CoverageInfos->begin();
    }
    auto GlobalIt = CoverageInfos->begin();
    //加锁
    {
      std::lock_guard<std::mutex> Lock(Mtx);
      for (auto &F : LocalCorpusSeeds) {
        auto U = FileToVector(F.File);
        std::vector<uint32_t> NewFeatures;
        std::vector<uintptr_t> SeedFuncs;
        std::vector<const TracePC::PCTableEntry *> SeedPCs;
        TPC.ResetMaps();
        int CBRes = 0;
        auto UnitStartTime = std::chrono::system_clock::now();
        CBRes = Callback(U.data(), U.size());
        auto UnitEndTime = std::chrono::system_clock::now();
        assert(CBRes == 0 || CBRes == -1);
        std::chrono::microseconds TimeOfUnit = std::chrono::duration_cast<std::chrono::microseconds>(UnitEndTime - UnitStartTime);
        TPC.CollectFeatures([&](uint32_t Feature){ NewFeatures.push_back(Feature); });
        TPC.UpdateObservedPCs(*FuzzerIt);
        TPC.UpdateObservedPCs(*GlobalIt);
        TPC.GetSeedTrace();
        TPC.ForEachCurrentObservedPC([&](const TracePC::PCTableEntry *TE){
          SeedPCs.push_back(TE);
          if (TPC.PcIsFuncEntry(TE)) {
            auto Func = TPC.GetNextInstructionPc(TE->PC);
            SeedFuncs.push_back(Func);
            if (Funcs.insert(Func).second) {Job->NewFuncs.push_back(Func);}
          }
          if (Cov.insert(TPC.PCTableEntryIdx(TE)).second) {Job->NewCov.push_back(TPC.PCTableEntryIdx(TE));}
        });
        MergeSeedInfo MergeSeedCandidate;
        MergeSeedCandidate.FilePath = F.File;
        MergeSeedCandidate.Size = F.Size;
        MergeSeedCandidate.Features = NewFeatures;
        MergeSeedCandidate.SeedFuncs = SeedFuncs;
        MergeSeedCandidate.SeedPCs = SeedPCs;
        MergeSeedCandidate.TimeOfUnit = TimeOfUnit;
        MergeSeedCandidates.push_back(MergeSeedCandidate);
      }
      TPC.GetFuncFreqsUncoveredInfo(*GlobalIt);
      TPC.GetFuncFreqsUncoveredInfo(*FuzzerIt);
    }
    //TODO
    //1.calculate the feedback of job and fuzzer
    //2.Merge coverage info
    //3.Update global corpus
    //加锁
    double JobFeedback = CalculateJobFeedback(Job, MergeSeedCandidates, *GlobalIt);
    //TODO
    //Sort MergeSeedCandidates by SortedWeight
    //1.Merge coverage info
    //2.Update global corpus
    SortMergeSeedCandidates(MergeSeedCandidates);
        //加锁
    {
      std::lock_guard<std::mutex> Lock(Mtx);
      for (size_t i = 0; i < MergeSeedCandidates.size(); i++){
        auto U = FileToVector(MergeSeedCandidates[i].FilePath);
        auto FileName = Hash(U);
        auto NewFilePath = DirPlusFile(MainCorpusDir, FileName);
        std::vector<uint32_t> TmpFeatureSet;
        size_t NumUpdatesBefore = GlobalCorpus->NumFeatureUpdates();
        //size_t NumFeaturesBefore = GlobalCorpus->NumFeatures();
        for (auto Feature : MergeSeedCandidates[i].Features){
          if (GlobalCorpus->AddFeature(Feature, MergeSeedCandidates[i].Size, &Features))
            TmpFeatureSet.push_back(Feature);
          GlobalCorpus->UpdateFeatureFrequency(nullptr, Feature);
        }
        size_t NumNewFeatures = GlobalCorpus->NumFeatureUpdates() - NumUpdatesBefore;
        //size_t NumNewAddedFeatures = GlobalCorpus->NumFeatures() - NumFeaturesBefore;
        if (NumNewFeatures > 0){
          WriteToFile(U, NewFilePath);
          SeedInfo *NewSI = GlobalCorpus->AddToCorpus(FileName, NewFilePath, NumNewFeatures,
                                                      std::chrono::microseconds(MergeSeedCandidates[i].TimeOfUnit), TmpFeatureSet,
                                                      MergeSeedCandidates[i].SeedPCs, MergeSeedCandidates[i].SeedFuncs);
        }
      }
    }
    //更新FuzzerStatuses
    {
      std::lock_guard<std::mutex> Lock(Mtx);
      auto FuzzerIt = FuzzerInfo::FindByName(FuzzerStatuses, Job->FuzzerName);
      if (FuzzerIt != FuzzerStatuses.end()) {
        if(Job->JobId < 8){
          FuzzerIt->Score += 10;
        }
        else{
          FuzzerIt->Score += JobFeedback;
        }
        FuzzerIt->CoveredBranches += Job->NewCov.size();
        FuzzerIt->UsedBudget += std::stod(Job->JobBudget);
      }
    }
    //打印输出：NumRuns Cov.size() Features.size() Job->JobId Seeds live
    //打印信息补充FuzzerName：JobFeedback：
    Printf("\tMergeJob Done: JobId: %zd, FuzzerName: %s, JobFeedback: %f, NumRuns: %zd, Cov: %zd, Features: %zd, Seeds: %zd\n", Job->JobId, Job->FuzzerName.c_str(), JobFeedback, NumRuns, Cov.size(), Features.size(), GlobalCorpus->GetLiveInputsSize());
    //将MergeJob信息写入LogPath
    std::ofstream LogFile(LogPath, std::ios::app);
    LogFile << "\tMergeJob Done: JobId: " << Job->JobId << ", FuzzerName: " << Job->FuzzerName << ", JobFeedback: " << JobFeedback << ", NumRuns: " << NumRuns << ", Cov: " << Cov.size() << ", Features: " << Features.size() << ", Seeds: " << GlobalCorpus->GetLiveInputsSize() << std::endl;
    LogFile.close();
    
    for (auto IDX : Job->NewCov){
      if (auto *TE = TPC.PCTableEntryByIdx(IDX)){
        if (TPC.PcIsFuncEntry(TE)){
        PrintPC("  NEW_FUNC: %p %F %L\n", "", TPC.GetNextInstructionPc(TE->PC));
        }
      }
    }   
  }

  void RunOneMergeJob(FuzzJob *Job) {
    auto Stats = ParseFinalStatsFromLog(Job->LogPath);
    NumRuns += Stats.number_of_executed_units;

    std::vector<SizedFile> TempFiles, MergeCandidates;
    // Read all newly created inputs and their feature sets.
    // Choose only those inputs that have new features.
    GetSizedFilesFromDir(Job->CorpusDir, &TempFiles);
    std::sort(TempFiles.begin(), TempFiles.end());
    for (auto &F : TempFiles) {
      auto FeatureFile = F.File;
      FeatureFile.replace(0, Job->CorpusDir.size(), Job->FeaturesDir);
      auto FeatureBytes = FileToVector(FeatureFile, 0, false);
      assert((FeatureBytes.size() % sizeof(uint32_t)) == 0);
      std::vector<uint32_t> NewFeatures(FeatureBytes.size() / sizeof(uint32_t));
      memcpy(NewFeatures.data(), FeatureBytes.data(), FeatureBytes.size());
      for (auto Ft : NewFeatures) {
        if (!Features.count(Ft)) {
          MergeCandidates.push_back(F);
          break;
        }
      }
    }
    // if (!FilesToAdd.empty() || Job->ExitCode != 0)
    Printf("#%zd: cov: %zd ft: %zd corp: %zd exec/s: %zd "
           "oom/timeout/crash: %zd/%zd/%zd time: %zds job: %zd\n",
           NumRuns, Cov.size(), Features.size(), Files.size(),
           Stats.average_exec_per_sec, NumOOMs, NumTimeouts, NumCrashes,
           secondsSinceProcessStartUp(), Job->JobId);

    if (MergeCandidates.empty()) return;

    std::vector<std::string> FilesToAdd;
    std::set<uint32_t> NewFeatures, NewCov;
    bool IsSetCoverMerge =
        !Job->Cmd.getFlagValue("set_cover_merge").compare("1");
    CrashResistantMerge(Args, {}, MergeCandidates, &FilesToAdd, Features,
                        &NewFeatures, Cov, &NewCov, Job->CFPath, false,
                        IsSetCoverMerge);
    for (auto &Path : FilesToAdd) {
      auto U = FileToVector(Path);
      auto NewPath = DirPlusFile(MainCorpusDir, Hash(U));
      WriteToFile(U, NewPath);
      if (Group) { // Insert the queue according to the size of the seed.
        size_t UnitSize = U.size();
        auto Idx =
            std::upper_bound(FilesSizes.begin(), FilesSizes.end(), UnitSize) -
            FilesSizes.begin();
        FilesSizes.insert(FilesSizes.begin() + Idx, UnitSize);
        Files.insert(Files.begin() + Idx, NewPath);
      } else {
        Files.push_back(NewPath);
      }
    }
    Features.insert(NewFeatures.begin(), NewFeatures.end());
    Cov.insert(NewCov.begin(), NewCov.end());
    for (auto Idx : NewCov)
      if (auto *TE = TPC.PCTableEntryByIdx(Idx))
        if (TPC.PcIsFuncEntry(TE))
          PrintPC("  NEW_FUNC: %p %F %L\n", "",
                  TPC.GetNextInstructionPc(TE->PC));
  }


};

struct JobQueue {
  std::queue<FuzzJob *> Qu;
  std::mutex Mu;
  std::condition_variable Cv;

  void Push(FuzzJob *Job) {
    {
      std::lock_guard<std::mutex> Lock(Mu);
      Qu.push(Job);
    }
    Cv.notify_one();
  }
  FuzzJob *Pop() {
    std::unique_lock<std::mutex> Lk(Mu);
    // std::lock_guard<std::mutex> Lock(Mu);
    Cv.wait(Lk, [&]{return !Qu.empty();});
    assert(!Qu.empty());
    auto Job = Qu.front();
    Qu.pop();
    return Job;
  }
};

void WorkerThread(JobQueue *FuzzQ, JobQueue *MergeQ) {
  while (auto Job = FuzzQ->Pop()) {
    // Printf("WorkerThread: job %p\n", Job);
    Job->ExitCode = ExecuteCommand(Job->Cmd);
    MergeQ->Push(Job);
  }
}

// This is just a skeleton of an experimental -fork=1 feature.
void FuzzWithFork(Random &Rand, const FuzzingOptions &Options,
                  const std::vector<std::string> &Args,
                  const std::vector<std::string> &CorpusDirs, 
                  int NumJobs, UserCallback Callback,
                  std::vector<std::string> Fuzzers) {
  Printf("INFO: -fork=%d: fuzzing in separate process(s)\n", NumJobs);

  GlobalEnv Env;
  Env.Args = Args;
  Env.CorpusDirs = CorpusDirs;
  Env.Rand = &Rand;
  Env.Callback = Callback;
  Env.Verbosity = Options.Verbosity;
  Env.ProcessStartTime = std::chrono::system_clock::now();
  //Env.DataFlowBinary = Options.CollectDataFlow;
  Env.Group = Options.ForkCorpusGroups;
  //Fuzzers preprocess 
  Env.Fuzzers = Fuzzers;
  if (Fuzzers.size() > 0) {
    Env.FuzzerStatuses.resize(Fuzzers.size());
    for (size_t i = 0; i < Fuzzers.size(); i++) {
      Env.FuzzerStatuses[i].Name = Fuzzers[i];
      Env.FuzzerStatuses[i].Selections = 0;
      Env.FuzzerStatuses[i].Score = 0;
      Env.FuzzerStatuses[i].CoveredBranches = 0;
      Env.FuzzerStatuses[i].UsedBudget = 0;
    }
    Printf("INFO: -fork=%d: fuzzing in separate process(s) with fuzzers: %s\n", NumJobs, Env.Fuzzers[0].c_str());
  }
  //我想用一个Vector来存在全局的CoverageInfo和每个fuzzer的CoverageInfo
  std::vector<TracePC::CoverageInfo> CoverageInfos;
  if (Fuzzers.size() > 1) {
    CoverageInfos.resize(Fuzzers.size() + 1);
    CoverageInfos[0].FuzzerName = "Global";
    CoverageInfos[0].ObservedPCs.clear();
    CoverageInfos[0].ObservedFuncs.clear();
    for (size_t i = 1; i < Fuzzers.size() + 1; i++) {
      CoverageInfos[i].FuzzerName = Fuzzers[i - 1];
      CoverageInfos[i].ObservedPCs.clear();
      CoverageInfos[i].ObservedFuncs.clear();
    }
  }
  else {
    CoverageInfos.resize(1);
    CoverageInfos[0].FuzzerName = "Global";
    CoverageInfos[0].ObservedPCs.clear();
    CoverageInfos[0].ObservedFuncs.clear();
  }

  std::vector<SizedFile> SeedFiles;
  for (auto &Dir : CorpusDirs)
    GetSizedFilesFromDir(Dir, &SeedFiles);
  std::sort(SeedFiles.begin(), SeedFiles.end());
  Env.TempDir = TempPath("FuzzWithFork", ".dir");
  RmDirRecursive(Env.TempDir);  // in case there is a leftover from old runs.
  MkDir(Env.TempDir);
  if (CorpusDirs.empty())
    MkDir(Env.MainCorpusDir = DirPlusFile(Env.TempDir, "C"));
  else
    Env.MainCorpusDir = CorpusDirs[0];

  if (Options.KeepSeed) {
    for (auto &File : SeedFiles)
      Env.Files.push_back(File.File);
  } else {
    auto CFPath = DirPlusFile(Env.TempDir, "merge.txt");
    std::set<uint32_t> NewFeatures, NewCov;
    CrashResistantMerge(Env.Args, {}, SeedFiles, &Env.Files, Env.Features,
                        &NewFeatures, Env.Cov, &NewCov, CFPath,
                        /*Verbose=*/false, /*IsSetCoverMerge=*/false);
    //Env.Features.insert(NewFeatures.begin(), NewFeatures.end());
    //Env.Cov.insert(NewCov.begin(), NewCov.end());
    RemoveFile(CFPath);
  }
  std::vector<SizedFile> FilesWithSize;
  for (auto &File : Env.Files)
    FilesWithSize.push_back({File, FileToVector(File).size()});
  
  //Long Features or small size priority?
  //获取当前ELF路径
  std::string CurrentPath = GetExeDirName();
  //获取目标程序
  std::string Target_Program = GetBaseName(Args[0]);
  Env.LogPath = DirPlusFile(CurrentPath, "Log.txt");
  Printf("CurrentPath: %s\n", CurrentPath.c_str());
  Printf("Target_Program: %s\n", Target_Program.c_str());
  GlobalCorpusInfo *GlobalCorpus = new GlobalCorpusInfo(Env.MainCorpusDir);
  ArgsInfo *AllArgsInfo = new ArgsInfo(CurrentPath, Target_Program);

  //Corpus preprocess
  for (size_t i = 0; i < FilesWithSize.size(); i++) {
    auto U = FileToVector(FilesWithSize[i].File);
    auto FileName = Hash(U);
    auto FilePath = DirPlusFile(Env.MainCorpusDir, FileName);
    std::vector<const TracePC::PCTableEntry *> SeedPCs;
    std::vector<uintptr_t> SeedFuncs;
    TPC.ResetMaps();
    int CBRes = 0;
    auto UnitStartTime = std::chrono::system_clock::now();
    CBRes = Callback(U.data(), U.size());
    auto UnitEndTime = std::chrono::system_clock::now();
    assert(CBRes == 0 || CBRes == -1);
    auto TimeOfUnit = std::chrono::duration_cast<std::chrono::microseconds>(UnitEndTime - UnitStartTime).count();
    std::vector<uint32_t> TmpFeatureSet;
    size_t NumUpdatesBefore = GlobalCorpus->NumFeatureUpdates();
    TPC.CollectFeatures([&](uint32_t Feature){
      if (GlobalCorpus->AddFeature(Feature, FilesWithSize[i].Size, &Env.Features))
        TmpFeatureSet.push_back(Feature);
      GlobalCorpus->UpdateFeatureFrequency(nullptr, Feature);
    });
    size_t NumNewFeatures = GlobalCorpus->NumFeatureUpdates() - NumUpdatesBefore;
    TPC.UpdateObservedPCs(CoverageInfos[0]);
    TPC.GetFuncFreqsUncoveredInfo(CoverageInfos[0]);
    if (NumNewFeatures > 0) {
      WriteToFile(U, FilePath);
      TPC.GetSeedTrace();
      TPC.ForEachCurrentObservedPC([&](const TracePC::PCTableEntry *TE){
        SeedPCs.push_back(TE);
        Env.Cov.insert(TPC.PCTableEntryIdx(TE));
        if (TPC.PcIsFuncEntry(TE)) {
          auto Func = TPC.GetNextInstructionPc(TE->PC);
          SeedFuncs.push_back(Func);
          Env.Funcs.insert(Func);
        }
      });
      SeedInfo *NewSI = GlobalCorpus->AddToCorpus(FilesWithSize[i].File, FilePath, NumNewFeatures,
                                                std::chrono::microseconds(TimeOfUnit), TmpFeatureSet,
                                                SeedPCs, SeedFuncs);
    }
  }

  if (Env.Group) {
    for (auto &path : Env.Files)
      Env.FilesSizes.push_back(FileSize(path));
  }

  Printf("INFO: -fork=%d: %zd seed inputs, starting to fuzz in %s\n", NumJobs,
         Env.Files.size(), Env.TempDir.c_str());

  int ExitCode = 0;

  JobQueue FuzzQ, MergeQ;

  auto StopJobs = [&]() {
    for (int i = 0; i < NumJobs; i++)
      FuzzQ.Push(nullptr);
    MergeQ.Push(nullptr);
    WriteToFile(Unit({1}), Env.StopFile());
  };


  size_t JobId = 1;
  std::vector<std::thread> Threads;
  for (int t = 0; t < NumJobs; t++) {
    Threads.push_back(std::thread(WorkerThread, &FuzzQ, &MergeQ));
    FuzzQ.Push(Env.CreateNewJob(JobId++, GlobalCorpus, &CoverageInfos, AllArgsInfo));
  }
  
  while (true) {
    //std::unique_ptr<FuzzJob> Job(MergeQ.Pop());
    FuzzJob *Job = MergeQ.Pop();
    if (!Job)
      break;
    ExitCode = Job->ExitCode;
    if (ExitCode == Options.InterruptExitCode) {
      Printf("==%lu== libFuzzer: a child was interrupted; exiting\n", GetPid());
      StopJobs();
      break;
    }
    Fuzzer::MaybeExitGracefully();
    // Since the number of corpus seeds will gradually increase, in order to
    // control the number in each group to be about three times the number of
    // seeds selected each time, the number of groups is dynamically adjusted.


    // Continue if our crash is one of the ignored ones.
    if (Options.IgnoreTimeouts && ExitCode == Options.TimeoutExitCode)
      Env.NumTimeouts++;
    else if (Options.IgnoreOOMs && ExitCode == Options.OOMExitCode)
      Env.NumOOMs++;
    else if (ExitCode != 0) {
      Env.NumCrashes++;
      if (Options.IgnoreCrashes) {
        std::ifstream In(Job->LogPath);
        std::string Line;
        while (std::getline(In, Line, '\n'))
          if (Line.find("ERROR:") != Line.npos ||
              Line.find("runtime error:") != Line.npos)
            Printf("%s\n", Line.c_str());
      } else {
        // And exit if we don't ignore this crash.
        Printf("INFO: log from the inner process:\n%s",
               FileToString(Job->LogPath).c_str());
        StopJobs();
        break;
      }
    }

    // Stop if we are over the time budget.
    // This is not precise, since other threads are still running
    // and we will wait while joining them.
    // We also don't stop instantly: other jobs need to finish.

    if (Options.MaxTotalTimeSec > 0 &&
        Env.secondsSinceProcessStartUp() >= (size_t)Options.MaxTotalTimeSec) {
      Printf("INFO: fuzzed for %zd seconds, wrapping up soon\n",
             Env.secondsSinceProcessStartUp());
      StopJobs();
      sleep(10);
      Env.RunOneMergeJob(Job, &CoverageInfos, GlobalCorpus);
      delete Job;
      break;
    }
    if (Env.NumRuns >= Options.MaxNumberOfRuns) {
      Printf("INFO: fuzzed for %zd iterations, wrapping up soon\n",
             Env.NumRuns);
      StopJobs();
      break;
    }

    std::thread([&Env, Job, &CoverageInfos, &GlobalCorpus] {
        //Env.RunOneMergeJob(Job.get());
      Env.RunOneMergeJob(Job, &CoverageInfos, GlobalCorpus);
      delete Job;
    }).detach();

    

    // Generate code: thread to create new job.
    std::thread([&FuzzQ, &Env, &JobId, &CoverageInfos, &GlobalCorpus, &AllArgsInfo] {
      {
        std::lock_guard<std::mutex> Lock(Env.Mtx);
        JobId++;
      }
      FuzzQ.Push(Env.CreateNewJob(JobId, GlobalCorpus, &CoverageInfos, AllArgsInfo));
    }).detach();
  }
  for (auto &T : Threads){
    if (T.joinable()){
      T.join();
    }
  }
  delete GlobalCorpus;
  delete AllArgsInfo;
  

  // The workers have terminated. Don't try to remove the directory before they
  // terminate to avoid a race condition preventing cleanup on Windows.
  RmDirRecursive(Env.TempDir);

  // Use the exit code from the last child process.
  Printf("INFO: exiting: %d time: %zds\n", ExitCode,
         Env.secondsSinceProcessStartUp());
  exit(ExitCode);
}

bool CopyFile(const std::string &SrcPath, const std::string &DstPath) {
    // Check if src file exists
    if (access(SrcPath.c_str(), F_OK) == -1) {
        return false;
    }
    // Check if src file is empty
    struct stat stat_buf;
    if (stat(SrcPath.c_str(), &stat_buf) != 0 || stat_buf.st_size == 0) {
        return false;
    }
    // Check if dst file exists
    if (access(DstPath.c_str(), F_OK) != -1) {
        return false;
    }
    // Copy file
    std::ifstream src(SrcPath, std::ios::binary);
    std::ofstream dst(DstPath, std::ios::binary);
    dst << src.rdbuf();
    return true;
}

std::string GetBaseName(const std::string &path) {
    size_t pos = path.find_last_of("/\\");
    if (pos != std::string::npos) {
        return path.substr(pos + 1);
    }
    return path;
}

void CopyMultipleFiles(const std::vector<SeedInfo *> &JobSeeds, const std::string &InputDir) {
    //Printf("CopyMultipleFiles: Starting copy process for %zu seeds\n", JobSeeds.size());
    if (!JobSeeds.empty()) {
        for (auto &SI : JobSeeds) {
            if (SI->Live) {
                std::string InputFilePath = SI->FilePath;
                std::string InputFileName = GetBaseName(SI->File);  // 只获取文件名部分
                std::string InputFileFullPath = DirPlusFile(InputDir, InputFileName);
                if (!CopyFile(InputFilePath, InputFileFullPath)) {
                    //Printf("Failed to copy file %s to %s\n", InputFilePath.c_str(), InputFileFullPath.c_str());
                    continue;
                }
            }
        }
    }
    else {
        //Printf("CopyMultipleFiles: No seeds provided, creating initial seeds\n");
        for (size_t i = 0; i < 2; i++){
            std::string FilNname = "nullseed";
            std::string TargetPath = InputDir + "/" + FilNname;
            std::ofstream file(TargetPath);
            if (file.is_open()) {
                file << "0x" + std::to_string(rand());
                file.close();
                //Printf("Created initial seed: %s\n", FilNname.c_str());
            }
            else {
                Printf("Failed to create initial seed: %s\n", FilNname.c_str());
            }
        }
    }
    //Printf("CopyMultipleFiles: Copy process completed\n");
}

std::string GetExeDirName(){
    char buffer[1024];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        // 找到最后一个'/'的位置
        char *last_slash = strrchr(buffer, '/');
        if (last_slash != nullptr) {
            // 将最后一个'/'替换为'\0'，这样就只保留目录部分
            *last_slash = '\0';
        }
        return std::string(buffer);
    }
    return "";
}


std::string GetLocalCorpusDir(const std::string &CorpusDir, const std::string &FuzzerName){
    //如果FuzzerName是libfuzzer 或者 entropic 或者wingfuzz或者honggfuzz，OUTPUT_DIR是CorpusDir
    //如果FuzzerName是aflplusplus 或者 radamsa 或者 mopt或者是lafintel或者 redqueen，OUTPUT_DIR是CorpusDir/default/queue
    //如果FuzzerName是afl 或者 aflfast 或者 fairfuzz，OUTPUT_DIR是CorpusDir/queue

    std::string OutputDir;
    if(FuzzerName == "libfuzzer" || FuzzerName == "entropic" || FuzzerName == "wingfuzz" || FuzzerName == "honggfuzz"){
        OutputDir = CorpusDir;
    }
    else if(FuzzerName == "symcc" || FuzzerName == "aflplusplus" || FuzzerName == "radamsa" || FuzzerName == "mopt" || FuzzerName == "lafintel" || FuzzerName == "redqueen" || FuzzerName == "hastefuzz"){
        OutputDir = CorpusDir + "/default/queue";
    }//增加darwin,ecofuzz,fafuzz,learnperffuzz,neuzz
    else if(FuzzerName == "afl" || FuzzerName == "aflfast" || FuzzerName == "aflgo" || FuzzerName == "fairfuzz" || FuzzerName == "darwin" || FuzzerName == "ecofuzz" || FuzzerName == "fafuzz"  || FuzzerName == "moptbk" || FuzzerName == "weizz"){
        OutputDir = CorpusDir + "/queue";
    }
    else{
        Printf("Unknown fuzzer: %s\n", FuzzerName.c_str());
    }
    return OutputDir;
}

std::string GetFuzzerName(std::vector<FuzzerInfo> &FuzzerStatuses, size_t JobId, std::string LogPath){
    size_t FuzzerCount = FuzzerStatuses.size();
    if(FuzzerCount == 0){
        return "entropic";
    }
    else{
        for(auto &Fuzzer : FuzzerStatuses){
            if(Fuzzer.Selections == 0){
                return Fuzzer.Name;
            }
        }
        //采用UCB1算法计算选择
        double UCB1Score = 0;
        std::vector<double> UCB1Scores;
        for(auto &Fuzzer : FuzzerStatuses){
            UCB1Score = Fuzzer.Score / Fuzzer.Selections + 2 * sqrt(log(JobId) / Fuzzer.Selections);
            UCB1Scores.push_back(UCB1Score);
        }
        std::vector<double> Probabilities;
        double Sum = 0;
        for(auto &Score : UCB1Scores){
            Sum += Score;
        }
        for(auto &Score : UCB1Scores){
            Probabilities.push_back(Score / Sum);
        }
        for(auto &Fuzzer : FuzzerStatuses){
           Printf("\tFuzzerStatus: Name: %s, TotalScore: %f, Selections: %zd, UCB1Score: %f, CoveredBranches: %zd, UsedBudget: %f\n", Fuzzer.Name.c_str(), Fuzzer.Score, Fuzzer.Selections, UCB1Scores[&Fuzzer - &FuzzerStatuses[0]], Fuzzer.CoveredBranches, Fuzzer.UsedBudget);
           //将FuzzerStatus写入LogPath
           std::ofstream LogFile(LogPath, std::ios::app);
           LogFile << "\tFuzzerStatus: Name: " << Fuzzer.Name << ", TotalScore: " << Fuzzer.Score << ", Selections: " << Fuzzer.Selections << ", UCB1Score: " << UCB1Scores[&Fuzzer - &FuzzerStatuses[0]] << ", CoveredBranches: " << Fuzzer.CoveredBranches << ", UsedBudget: " << Fuzzer.UsedBudget << std::endl;
           LogFile.close();
        }
        std::random_device rd;
        std::mt19937 gen(rd());
        std::discrete_distribution<> d(Probabilities.begin(), Probabilities.end());
        return FuzzerStatuses[d(gen)].Name;
    }
    return "entropic";
}

double CalculateJobFeedback(FuzzJob *Job, std::vector<MergeSeedInfo> &MergeSeedCandidates, TracePC::CoverageInfo &GlobalIt){
    double JobFeedback = 0;
    size_t GlobalAverageHits = GlobalIt.FuncsAverageHits;
    std::unordered_map<uintptr_t, double> FuncWeightMap;
    for (const auto &Func : GlobalIt.FuncsInfo){
        FuncWeightMap[Func.Id] = Func.GetWeight(GlobalAverageHits);
    }
    size_t FuncCount = 0;
    
    for (auto &Seed : MergeSeedCandidates){
        double SeedWeight = 0;
        for (auto &Func : Seed.SeedFuncs){
            std::string FileStr = DescribePC("%s", Func);
            if (!IsInterestingCoverageFile(FileStr)) continue;
            if (FuncWeightMap.find(Func) != FuncWeightMap.end()){
                JobFeedback += FuncWeightMap[Func];
                SeedWeight += FuncWeightMap[Func];
                FuncCount++;
            }
            else{
                JobFeedback += 100;
                SeedWeight += 100;
            }
        }
        Seed.SortedWeight = SeedWeight;
    }
    if (FuncCount > 0) JobFeedback /= FuncCount;
    return JobFeedback;
}

void SortMergeSeedCandidates(std::vector<MergeSeedInfo> &MergeSeedCandidates){
    std::sort(MergeSeedCandidates.begin(), MergeSeedCandidates.end(), [](const MergeSeedInfo &a, const MergeSeedInfo &b){
        return a.SortedWeight > b.SortedWeight;
    });
}

} // namespace fuzzer
