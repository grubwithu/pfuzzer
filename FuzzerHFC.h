#pragma one
#ifndef FUZZER_HFC_H
#define FUZZER_HFC_H

#include "FuzzerTracePC.h"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>

namespace fuzzer {

using json = nlohmann::json;

httplib::Client *GetHTTPClient();

struct PeekResultResponce {
  std::vector<ConstraintGroup> ConstraintGroups;
  std::unordered_map</*Fuzzer*/ std::string, std::unordered_map</*Constraint*/ std::string, double>> FuzzerScores;
  std::unordered_map</*Fuzzer*/ std::string, int> FuzzerCovInc;
};

std::unique_ptr<PeekResultResponce> PeekResult();
void ReportCorpus(std::string FuzzerName, std::string Identity, std::vector<std::string> Corpus);
void Log(std::string Log);

} // namespace fuzzer

#endif