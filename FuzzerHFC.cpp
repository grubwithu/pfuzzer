// DEPRECATED compatibility shim: implements the V1-signature entry points
// that pfuzzer's FuzzerFork.cpp calls, delegating to the V2 client in
// FuzzerOrchestra.{h,cpp} over /v2/*. Retained one release cycle
// (CONTRACTS.md §11).
//
// Mapping (FuzzerFork.cpp call sites → V2 endpoints):
//   Ready()                          → GET  /v2/health
//   PeekResult()                     → GET  /v2/frontiers/active
//                                      (+ GET /v2/dictionary for DictContent)
//   ReportCorpus(..., "begin"/"end"/
//                "summary", {dirs})  → POST /v2/corpus/add per file via
//                                      inline seed_data bytes; fork-mode temp
//                                      files are transient, so a shared path
//                                      cannot be replayed after the fork
//                                      child exits. The server's at-most-once
//                                      store makes repeat reports cheap.
//   Log(...)                         → engine-local Printf (no V2 endpoint)
//
// V1 concepts with no V2 equivalent:
//   SelectedFuzzer stays empty → FuzzerFork downgrades to its UCB1 engine
//   strategy; engine selection is owned by pfuzzer (DESIGN.md §6).
//   Root-to-leaf Path and per-fuzzer ConstraintScore stay empty; V2 carries
//   the frontier key and a frontier-level score.
#include "FuzzerHFC.h"
#include "FuzzerOrchestra.h"

#include "FuzzerIO.h"
#include "nlohmann/json.hpp"

#include <dirent.h>

#include <fstream>
#include <iterator>
#include <string>
#include <sys/stat.h>
#include <vector>

namespace fuzzer {

httplib::Client *GetHTTPClient() { return GetOrchestraClient(); }

bool Ready() { return OrchestraHealth(); }

std::unique_ptr<PeekResultResponce> PeekResult() {
  auto Response = std::make_unique<PeekResultResponce>();
  auto Recs = OrchestraGetActiveFrontiers();
  if (Recs && !Recs->Frontiers.empty()) {
    auto &Front = Recs->Frontiers.front();
    Response->ConstraintGroup.GroupId = Front.FrontierKey;
    Response->ConstraintGroup.LeafFunction = Front.FrontierKey;
    Response->ConstraintGroup.Importance = Front.Score;
    if (!Front.RecommendedSeeds.empty())
      Printf("Orchestra frontier %s: %zu recommended seeds\n",
             Front.FrontierKey.c_str(), Front.RecommendedSeeds.size());
  }
  // Dictionary: libFuzzer dict format, one entry per mined token.
  auto Dict = OrchestraGetDictionary();
  if (Dict && !Dict->Tokens.empty()) {
    std::string Content;
    int Idx = 1;
    for (auto &Token : Dict->Tokens) {
      Content += "token" + std::to_string(Idx++) + "=\"" + Token + "\"\n";
    }
    Response->DictContent = Content;
  }
  return Response;
}

// ListFiles returns the regular files directly inside Dir (corpora
// directories are flat). Linux/Docker target; the shim retires after one
// release cycle so the POSIX-only listing is acceptable.
static std::vector<std::string> ListFiles(const std::string &Dir) {
  std::vector<std::string> Files;
  DIR *D = opendir(Dir.c_str());
  if (!D)
    return Files;
  while (auto Entry = readdir(D)) {
    std::string Name = Entry->d_name;
    if (Name == "." || Name == "..")
      continue;
    std::string Full = Dir + "/" + Name;
    struct stat S;
    if (stat(Full.c_str(), &S) == 0 && S_ISREG(S.st_mode))
      Files.push_back(Full);
  }
  closedir(D);
  return Files;
}

void ReportCorpus(std::string FuzzerName, size_t JobId, size_t JobBudget,
                  std::string period, std::vector<std::string> Corpus,
                  const std::unordered_map<std::string, std::vector<uint32_t>> &SeedHints) {
  (void)JobBudget; // V2 budgets are scheduler-side.
  (void)period;    // begin/end/summary all reduce to at-most-once seed reports.
  for (auto &Path : Corpus) {
    for (auto &File : ListFiles(Path)) {
      // Inline transport (seed_data): fork-mode temp files are transient —
      // libFuzzer removes them when the process exits, so the analyzer
      // cannot replay them through a shared path after the fork child is
      // gone. Reading the bytes here lets the analyzer hash and measure
      // what this engine actually reported.
      std::ifstream In(File, std::ios::binary);
      if (!In) {
        Printf("Orchestra: cannot read seed %s\n", File.c_str());
        continue;
      }
      std::vector<uint8_t> Bytes((std::istreambuf_iterator<char>(In)),
                                 std::istreambuf_iterator<char>());
      std::vector<uint32_t> Hint;
      auto It = SeedHints.find(File);
      if (It != SeedHints.end()) {
        Hint = It->second;
      }
      auto Res =
          OrchestraAddCorpusData(FuzzerName, std::to_string(JobId), std::string(), Bytes, Hint);
      if (Res && Res->HintDiverged) {
        Printf("Orchestra: hint diverged for seed %s (ratio %f); keeping local bitmap\n",
               File.c_str(), Res->DivergenceRatio);
      }
    }
  }
}

void Log(std::string Log) {
  // V2 has no log endpoint; strategy changes stay engine-local.
  Printf("%s\n", Log.c_str());
}

} // namespace fuzzer
