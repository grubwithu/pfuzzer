#include "FuzzerHFC.h"
#include "nlohmann/json.hpp" 
#include "FuzzerIO.h"

namespace fuzzer {

using json = nlohmann::json;

httplib::Client *GetHTTPClient() {
  static httplib::Client *Client = nullptr;
  if (!Client) {
    auto HfcUrl = getenv("HFC_URL");
    if (HfcUrl) {
      Client = new httplib::Client(HfcUrl);
    } else {
      // std::cerr << "HFC_URL is not set, using localhost:8080" << std::endl;
      Printf("HFC_URL is not set, using localhost:8080\n");
      Client = new httplib::Client("localhost", 8080);
    }
  }
  return Client;
}

std::unique_ptr<PeekResultResponce> PeekResult() {
  auto &Client = *GetHTTPClient();
  auto Res = Client.Get("/peekResult");
  auto response = std::make_unique<PeekResultResponce>();
  auto &ConstraintGroup = response->ConstraintGroup;
  auto &FuzzerScores = response->FuzzerScores;
  if (Res && Res->status == 200 && !Res->body.empty()) {
    auto JsonRes = json::parse(Res->body, nullptr, false);
    if (!JsonRes.contains("data") || !JsonRes["data"].contains("plugin_results")) {
      // std::cerr << "peekResult reponse body is not valid, please check hfc is running correctly." << std::endl;
      Printf("peekResult reponse body is not valid, please check hfc is running correctly.\n");
      return nullptr;
    }
    auto &PluginResults = JsonRes["data"]["plugin_results"];
    
    // handle fuzzer_scores
    if (PluginResults.contains("fuzzer")) {
      if (PluginResults["fuzzer"].contains("fuzzer_scores")) {
        FuzzerScores = PluginResults["fuzzer"]["fuzzer_scores"];
      }
      if (PluginResults["fuzzer"].contains("selected_fuzzer")) {
        response->SelectedFuzzer = PluginResults["fuzzer"]["selected_fuzzer"];
      }
    }
    
    // handle constraint_group
    if (PluginResults.contains("seed") && PluginResults["seed"].contains("constraint_group")) {
      auto &Group = PluginResults["seed"]["constraint_group"];
      ConstraintGroup.GroupId = Group["group_id"];
      ConstraintGroup.LeafFunction = Group["leaf_function"];
      ConstraintGroup.FileName = Group["file_name"];
      ConstraintGroup.Importance = Group["importance"];
      // 处理 Path
      ConstraintGroup.Path.clear();
      for (auto &P : Group["path"]) {
        ConstraintGroup.Path.push_back(P);
      }
      // 处理 ConstraintScore
      ConstraintGroup.ConstraintScore = Group["constraint_score"];
      // 打印信息
      // std::cerr << "GroupId: " << ConstraintGroup.GroupId << " LeafFunction: " << ConstraintGroup.LeafFunction << " Importance: " << ConstraintGroup.Importance << std::endl;
      Printf("GroupId: %s LeafFunction: %s Importance: %f\n", ConstraintGroup.GroupId.c_str(), ConstraintGroup.LeafFunction.c_str(), ConstraintGroup.Importance);
      // std::cerr << "Path: ";
      Printf("Path: ");
      for (auto &P : ConstraintGroup.Path) {
        Printf("%s ", P.c_str());
      }
      Printf("\n");
    }

    // handle dict
    if (PluginResults.contains("dict") && PluginResults["dict"].contains("content")) {
      std::string DictContent = PluginResults["dict"]["content"];
      response->DictContent = DictContent;
      Printf("Dict file size: %d\n\n", DictContent.size());
    }
  }
  return response;
}

void ReportCorpus(std::string FuzzerName, size_t JobId, size_t JobBudget, std::string period, std::vector<std::string> Corpus) {
  auto &Client = *GetHTTPClient();
  json Body = {
      {"fuzzer", FuzzerName},
      {"identity", FuzzerName},
      {"job_id", JobId},
      {"job_budget", JobBudget},
      {"period", period},
      {"corpus", Corpus},
  };
  auto Res = Client.Post("/reportCorpus", Body.dump(), "application/json");
  if (Res) {
    if (Res->status != 200) {
      // std::cerr << "Report corpus failed: " << Res->body << std::endl;
      Printf("Report corpus failed: %s\n", Res->body.c_str());
    }
  }
}

void Log(std::string Log) {
  auto &Client = *GetHTTPClient();
  json Body = {
      {"log", Log},
  };
  auto Res = Client.Post("/log", Body.dump(), "application/json");
  if (Res) {
    if (Res->status != 200) {
      // std::cerr << "Log failed: " << Res->body << std::endl;
      Printf("Log failed: %s\n", Res->body.c_str());
    }
  }
}

bool Ready() {
  auto &Client = *GetHTTPClient();
  auto Res = Client.Get("/ready");
  if (Res) {
    auto JsonRes = json::parse(Res->body);
    if (JsonRes.contains("success") && JsonRes["success"].is_boolean()) {
      return JsonRes["success"];  
    }
  }
  return false;
}

} // namespace fuzzer
