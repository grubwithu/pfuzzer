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

struct ConstraintGroup {
  std::string GroupId;
  std::string Function;
  double Importance;
  std::vector<std::vector<std::string>> Paths;
  std::unordered_map<std::string, double> ConstraintScores;

}; // From HFC

// using json = nlohmann::json;

httplib::Client *GetHTTPClient();

struct PeekResultResponce {
  std::vector<ConstraintGroup> ConstraintGroups;
  std::unordered_map</*Fuzzer*/ std::string, std::unordered_map</*Constraint*/ std::string, double>> FuzzerScores;
  std::unordered_map</*Fuzzer*/ std::string, int> FuzzerCovInc;
};

std::unique_ptr<PeekResultResponce> PeekResult();
void ReportCorpus(std::string FuzzerName, std::string Identity, std::string period, std::vector<std::string> Corpus);
void Log(std::string Log);
bool Ready();

} // namespace fuzzer

#endif