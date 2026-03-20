#include "FuzzerHFC.h"
#include "nlohmann/json.hpp" 

namespace fuzzer {

using json = nlohmann::json;

httplib::Client *GetHTTPClient() {
  static httplib::Client *Client = nullptr;
  if (!Client) {
    auto HfcUrl = getenv("HFC_URL");
    if (HfcUrl) {
      Client = new httplib::Client(HfcUrl);
    } else {
      std::cerr << "HFC_URL is not set, using localhost:8080" << std::endl;
      Client = new httplib::Client("localhost", 8080);
    }
  }
  return Client;
}

std::unique_ptr<PeekResultResponce> PeekResult() {
  auto &Client = *GetHTTPClient();
  auto Res = Client.Get("/peekResult");
  auto response = std::make_unique<PeekResultResponce>();
  auto &ConstraintGroups = response->ConstraintGroups;
  auto &FuzzerScores = response->FuzzerScores;
  if (Res) {
    if (Res->status != 200) {
      std::cerr << "Recommend function failed: " << Res->body << std::endl;
    }
    auto JsonRes = json::parse(Res->body);
    if (!JsonRes.contains("data") || !JsonRes["data"].contains("constraint_groups")) {
      std::cerr << "peekResult reponse body is not valid, please check hfc is running correctly." << std::endl;
    }
    if (JsonRes["data"]["constraint_groups"].is_array()) {
      for (auto &Group : JsonRes["data"]["constraint_groups"]) {
        ConstraintGroup CG;
        CG.GroupId = Group["group_id"];
        CG.Function = Group["function"];
        CG.Importance = Group["importance"];
        CG.Paths = Group["paths"];
        // Print CGroup.Paths
        std::cerr << "GroupId: " << CG.GroupId << " Function: " << CG.Function << " Importance: " << CG.Importance << std::endl;
        for (auto &Path : CG.Paths) {
          for (auto &P : Path) {
            std::cerr << P << " ";
          }
          std::cerr << std::endl;
        }
        ConstraintGroups.push_back(CG);
      }
    }

    if (JsonRes["data"]["fuzzer_scores"].is_object()) {
      FuzzerScores = JsonRes["data"]["fuzzer_scores"];
    }
    if (JsonRes["data"]["fuzzer_cov_inc"].is_object()) {
      response->FuzzerCovInc = JsonRes["data"]["fuzzer_cov_inc"];
    }
  }
  return response;
}

void ReportCorpus(std::string FuzzerName, std::string Identity, std::string period, std::vector<std::string> Corpus) {
  auto &Client = *GetHTTPClient();
  json Body = {
      {"fuzzer", FuzzerName},
      {"identity", Identity},
      {"period", period},
      {"corpus", Corpus},
  };
  auto Res = Client.Post("/reportCorpus", Body.dump(), "application/json");
  if (Res) {
    if (Res->status != 200) {
      std::cerr << "Report corpus failed: " << Res->body << std::endl;
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
      std::cerr << "Log failed: " << Res->body << std::endl;
    }
  }
}

} // namespace fuzzer
