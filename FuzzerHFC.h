// DEPRECATED: V1-signature compatibility surface. pfuzzer's FuzzerFork.cpp
// calls these entry points; this header keeps their declarations unchanged so
// the submodule compiles untouched, while FuzzerHFC.cpp delegates to the V2
// client in FuzzerOrchestra.{h,cpp} over /v2/*. Retained one release cycle
// (CONTRACTS.md §11).
#pragma one
#ifndef FUZZER_HFC_H
#define FUZZER_HFC_H

#include "httplib.h"
// #include "nlohmann/json.hpp"
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>

namespace fuzzer {

typedef std::unordered_map<std::string, double> ConstraintScore;

struct ConstraintGroup {
  std::string GroupId;
  std::string LeafFunction;
  std::string FileName;
  double Importance;
  std::vector<std::string> Path;
  ConstraintScore ConstraintScore;
}; // From HFC

// using json = nlohmann::json;

httplib::Client *GetHTTPClient();

struct PeekResultResponce {
  ConstraintGroup ConstraintGroup;
  std::unordered_map<std::string, ConstraintScore> FuzzerScores;
  std::string SelectedFuzzer;
  std::string DictContent;
  // Orchestra V2: the selected frontier's recommended seed hashes (analyzer-
  // verified SHA-256 identities). Consumed via ResolveSeedPaths into local
  // file paths; CONTRACTS.md §5 — Orchestra recommends, pfuzzer executes.
  std::vector<std::string> RecommendedSeedHashes;
};

std::unique_ptr<PeekResultResponce> PeekResult();
// ResolveSeedPaths maps analyzer-verified seed hashes to local file paths
// recorded when this process posted the corpus. Hashes with no local copy
// (or whose file has vanished) are skipped; order follows the input.
std::vector<std::string> ResolveSeedPaths(const std::vector<std::string> &Hashes);
// SeedHints maps an absolute seed file path to the edge IDs the engine
// observed while replaying that seed in-process (Orchestra edge-ID space).
// Hints are engine observations only; the analyzer never trusts them
// (CONTRACTS.md §10). Merge jobs pass the map; "begin"/"summary" call
// sites pass the default empty map.
void ReportCorpus(std::string FuzzerName, size_t JobId, size_t JobBudget, std::string period, std::vector<std::string> Corpus,
                  const std::unordered_map<std::string, std::vector<uint32_t>> &SeedHints = {});
void Log(std::string Log);
bool Ready();

} // namespace fuzzer

#endif
