#pragma one
#ifndef FUZZER_HFC_H
#define FUZZER_HFC_H

#include "FuzzerTracePC.h"
#include "httplib.h"
#include "nlohmann/json.hpp"
#include <memory>

namespace fuzzer {

using json = nlohmann::json;

httplib::Client *GetHTTPClient();

struct PeekResultResponce {
  std::vector<ConstraintGroup> ConstraintGroups;
  std::unordered_map</*Fuzzer*/ std::string, std::unordered_map</*Constraint*/ std::string, double>> FuzzerScores;
};

std::unique_ptr<PeekResultResponce> PeekResult();

} // namespace fuzzer

#endif