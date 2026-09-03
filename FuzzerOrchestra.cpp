#include "FuzzerOrchestra.h"

#include "FuzzerIO.h"
#include "httplib.h"
#include "nlohmann/json.hpp"

#include <string>

namespace fuzzer {

using json = nlohmann::json;

static const uint64_t kWireSchemaVersion = 1;

httplib::Client *GetOrchestraClient() {
  static httplib::Client *Client = nullptr;
  if (!Client) {
    auto Url = getenv("ORCHESTRA_URL");
    if (Url) {
      Client = new httplib::Client(Url);
    } else {
      Printf("ORCHESTRA_URL is not set, using localhost:8080\n");
      Client = new httplib::Client("localhost", 8080);
    }
    // Bound the HTTP budget: fuzzing must never block on the analyzer
    // (DESIGN.md §8). Responses are cached engine-side for guidance.
    Client->set_connection_timeout(2, 0);
    Client->set_read_timeout(5, 0);
    Client->set_write_timeout(5, 0);
    Client->set_keep_alive(true);
  }
  return Client;
}

bool OrchestraEnabled() { return getenv("ORCHESTRA_URL") != nullptr; }

bool OrchestraHealth() {
  auto Res = GetOrchestraClient()->Get("/v2/health");
  if (!Res || Res->status != 200)
    return false;
  auto Json = json::parse(Res->body, nullptr, false);
  if (Json.is_discarded() || !Json.contains("status") ||
      !Json["status"].is_string())
    return false;
  return Json["status"].get<std::string>() == "ok";
}

std::unique_ptr<OrchestraState> OrchestraGetState() {
  auto Res = GetOrchestraClient()->Get("/v2/state");
  if (!Res || Res->status != 200)
    return nullptr;
  auto Json = json::parse(Res->body, nullptr, false);
  if (Json.is_discarded())
    return nullptr;
  auto Out = std::make_unique<OrchestraState>();
  Out->ModelId = Json.value("model_id", std::string());
  Out->StateVersion = Json.value("state_version", (uint64_t)0);
  Out->FrontierCount = Json.value("frontier_count", 0);
  Out->ActiveCount = Json.value("active_count", 0);
  Out->CoverageSize = Json.value("coverage_size", 0);
  return Out;
}

std::unique_ptr<OrchestraActiveFrontiers> OrchestraGetActiveFrontiers() {
  auto Res = GetOrchestraClient()->Get("/v2/frontiers/active");
  if (!Res || Res->status != 200)
    return nullptr;
  auto Json = json::parse(Res->body, nullptr, false);
  if (Json.is_discarded())
    return nullptr;
  auto Out = std::make_unique<OrchestraActiveFrontiers>();
  Out->StateVersion = Json.value("state_version", (uint64_t)0);
  if (Json.contains("frontiers") && Json["frontiers"].is_array()) {
    for (auto &F : Json["frontiers"]) {
      OrchestraFrontier Front;
      Front.FrontierKey = F.value("frontier_key", std::string());
      Front.TrueEdgeId = F.value("true_edge_id", (uint32_t)0);
      Front.FalseEdgeId = F.value("false_edge_id", (uint32_t)0);
      Front.CoveredEdgeId = F.value("covered_edge_id", (uint32_t)0);
      Front.UncoveredEdgeId = F.value("uncovered_edge_id", (uint32_t)0);
      Front.Starvation = F.value("starvation", 0.0);
      Front.Score = F.value("score", 0.0);
      if (F.contains("recommended_seed_hashes") &&
          F["recommended_seed_hashes"].is_array()) {
        for (auto &S : F["recommended_seed_hashes"]) {
          if (S.is_string())
            Front.RecommendedSeeds.push_back(S.get<std::string>());
        }
      }
      if (F.contains("dictionary_tokens") &&
          F["dictionary_tokens"].is_array()) {
        for (auto &T : F["dictionary_tokens"]) {
          if (T.is_string())
            Front.DictionaryTokens.push_back(T.get<std::string>());
        }
      }
      Out->Frontiers.push_back(std::move(Front));
    }
  }
  return Out;
}

std::unique_ptr<OrchestraDictionary> OrchestraGetDictionary() {
  auto Res = GetOrchestraClient()->Get("/v2/dictionary");
  if (!Res || Res->status != 200)
    return nullptr;
  auto Json = json::parse(Res->body, nullptr, false);
  if (Json.is_discarded())
    return nullptr;
  auto Out = std::make_unique<OrchestraDictionary>();
  Out->ModelId = Json.value("model_id", std::string());
  if (Json.contains("tokens") && Json["tokens"].is_array()) {
    for (auto &T : Json["tokens"]) {
      if (T.is_string())
        Out->Tokens.push_back(T.get<std::string>());
    }
  }
  return Out;
}

static const char kBase64Chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string Base64Encode(const std::vector<uint8_t> &Data) {
  std::string Out;
  Out.reserve((Data.size() + 2) / 3 * 4);
  size_t i = 0;
  while (i + 2 < Data.size()) {
    uint32_t Triple = (Data[i] << 16) | (Data[i + 1] << 8) | Data[i + 2];
    Out += kBase64Chars[(Triple >> 18) & 0x3F];
    Out += kBase64Chars[(Triple >> 12) & 0x3F];
    Out += kBase64Chars[(Triple >> 6) & 0x3F];
    Out += kBase64Chars[Triple & 0x3F];
    i += 3;
  }
  if (i + 1 == Data.size()) {
    uint32_t Triple = Data[i] << 16;
    Out += kBase64Chars[(Triple >> 18) & 0x3F];
    Out += kBase64Chars[(Triple >> 12) & 0x3F];
    Out += "==";
  } else if (i + 2 == Data.size()) {
    uint32_t Triple = (Data[i] << 16) | (Data[i + 1] << 8);
    Out += kBase64Chars[(Triple >> 18) & 0x3F];
    Out += kBase64Chars[(Triple >> 12) & 0x3F];
    Out += kBase64Chars[(Triple >> 6) & 0x3F];
    Out += "=";
  }
  return Out;
}

static std::unique_ptr<OrchestraCorpusAddResult>
PostCorpusAdd(const json &Body) {
  auto Res =
      GetOrchestraClient()->Post("/v2/corpus/add", Body.dump(), "application/json");
  // 2xx and 503 carry a parseable CorpusAddResponse envelope; 503 reports
  // verification_status "unavailable". Everything else is a hard transport
  // failure: fail soft.
  if (!Res || Res->status >= 500)
    return nullptr;
  auto Json = json::parse(Res->body, nullptr, false);
  if (Json.is_discarded())
    return nullptr;
  auto Out = std::make_unique<OrchestraCorpusAddResult>();
  Out->SeedHash = Json.value("seed_hash", std::string());
  Out->Verified = Json.value("verified", false);
  Out->VerificationStatus = Json.value("verification_status", std::string());
  Out->HintDiverged = Json.value("hint_diverged", false);
  Out->DivergenceRatio = Json.value("divergence_ratio", 0.0);
  return Out;
}

std::unique_ptr<OrchestraCorpusAddResult> OrchestraAddCorpusData(
    const std::string &FuzzerId, const std::string &JobId,
    const std::string &ParentSeedHash, const std::vector<uint8_t> &SeedData,
    const std::vector<uint32_t> &HintBitmap) {
  json Body = {
      {"schema_version", kWireSchemaVersion},
      {"fuzzer_id", FuzzerId},
      {"seed_data", Base64Encode(SeedData)},
  };
  if (!JobId.empty())
    Body["job_id"] = JobId;
  if (!ParentSeedHash.empty())
    Body["parent_seed_hash"] = ParentSeedHash;
  if (!HintBitmap.empty())
    Body["hint_bitmap"] = HintBitmap;
  return PostCorpusAdd(Body);
}

std::unique_ptr<OrchestraCorpusAddResult> OrchestraAddCorpusPath(
    const std::string &FuzzerId, const std::string &JobId,
    const std::string &ParentSeedHash, const std::string &SeedPath,
    const std::vector<uint32_t> &HintBitmap) {
  json Body = {
      {"schema_version", kWireSchemaVersion},
      {"fuzzer_id", FuzzerId},
      {"seed_path", SeedPath},
  };
  if (!JobId.empty())
    Body["job_id"] = JobId;
  if (!ParentSeedHash.empty())
    Body["parent_seed_hash"] = ParentSeedHash;
  if (!HintBitmap.empty())
    Body["hint_bitmap"] = HintBitmap;
  return PostCorpusAdd(Body);
}

bool OrchestraReportCoverage(
    const std::string &FuzzerId, const std::string &JobId,
    const std::vector<uint32_t> &ObservedBitmap,
    const std::vector<std::string> &AttemptedFrontiers,
    const std::vector<std::string> &CrossedFrontiers) {
  json Body = {
      {"schema_version", kWireSchemaVersion},
      {"fuzzer_id", FuzzerId},
  };
  if (!JobId.empty())
    Body["job_id"] = JobId;
  if (!ObservedBitmap.empty())
    Body["observed_bitmap"] = ObservedBitmap;
  if (!AttemptedFrontiers.empty())
    Body["attempted_frontier_ids"] = AttemptedFrontiers;
  if (!CrossedFrontiers.empty())
    Body["crossed_frontier_ids"] = CrossedFrontiers;
  auto Res = GetOrchestraClient()->Post("/v2/coverage/report", Body.dump(),
                                        "application/json");
  return Res && Res->status == 200;
}

} // namespace fuzzer
