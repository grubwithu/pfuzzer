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
};

std::unique_ptr<PeekResultResponce> PeekResult();
void ReportCorpus(std::string FuzzerName, size_t JobId, size_t JobBudget, std::string period, std::vector<std::string> Corpus);
void Log(std::string Log);
bool Ready();

} // namespace fuzzer

#endif
