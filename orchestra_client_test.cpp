// Standalone connection test for the pfuzzer V2 Orchestra client.
//
// Starts a mock analyzer (httplib::Server) on an ephemeral loopback port,
// points the client at it via ORCHESTRA_URL, and exercises every /v2/* call
// plus the deprecated V1-signature shim (Ready/PeekResult/ReportCorpus/Log).
// Finally stops the server and pins the soft-fail semantics: connection
// failures must return false/nullptr, never crash.
//
// Build (repo root):
//   g++ -std=c++17 -pthread -w -fpermissive -DCPPHTTPLIB_NO_EXCEPTIONS \
//     -I pfuzzer -I pfuzzer/third-party/cpp-httplib \
//     -I pfuzzer/third-party/json/include \
//     pfuzzer-hfc-patch/orchestra_client_test.cpp \
//     pfuzzer-hfc-patch/FuzzerOrchestra.cpp \
//     pfuzzer-hfc-patch/FuzzerHFC.cpp \
//     -o build/v2/bin/orchestra_client_test
//
// Exit 0 = all checks passed.
#include "FuzzerHFC.h"
#include "FuzzerOrchestra.h"

#include "httplib.h"
#include "nlohmann/json.hpp"

#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

using namespace fuzzer; // NOLINT

// Standalone stub for fuzzer::Printf (normally defined in FuzzerIO.cpp; the
// stub keeps this test from linking half of libFuzzer).
namespace fuzzer {
void Printf(const char *Fmt, ...) {
  va_list Ap;
  va_start(Ap, Fmt);
  vfprintf(stdout, Fmt, Ap);
  va_end(Ap);
}
} // namespace fuzzer

static int Failures = 0;

static void Check(bool Cond, const std::string &Msg) {
  if (Cond) {
    printf("PASS: %s\n", Msg.c_str());
  } else {
    fprintf(stderr, "FAIL: %s\n", Msg.c_str());
    Failures++;
  }
}

int main() {
  namespace fs = std::filesystem;

  httplib::Server Srv;
  std::atomic<bool> ProbeFail{false};
  std::string LastCorpusBody;
  std::atomic<int> CorpusCalls{0};

  Srv.Get("/v2/health", [](const httplib::Request &, httplib::Response &Res) {
    Res.set_content(R"({"status":"ok","api_version":"v2","model_id":"model-1"})",
                    "application/json");
  });
  Srv.Get("/v2/state", [](const httplib::Request &, httplib::Response &Res) {
    Res.set_content(
        R"({"schema_version":1,"model_id":"model-1","state_version":4,"frontier_count":2,"active_count":1,"coverage_size":1024})",
        "application/json");
  });
  Srv.Get("/v2/frontiers/active",
          [](const httplib::Request &, httplib::Response &Res) {
            Res.set_content(
                R"({"schema_version":1,"state_version":4,"frontiers":[{)"
                R"("frontier_key":"f1","true_edge_id":10,"false_edge_id":11,)"
                R"("covered_edge_id":10,"uncovered_edge_id":11,)"
                R"("starvation":0.5,"score":0.55,)"
                R"("recommended_seed_hashes":["seed-hash-1"],)"
                R"("dictionary_tokens":["edge_10","const_42"]}]})",
                "application/json");
          });
  Srv.Post("/v2/corpus/add",
           [&](const httplib::Request &Req, httplib::Response &Res) {
             LastCorpusBody = Req.body;
             CorpusCalls++;
             if (ProbeFail) {
               Res.set_content(
                   R"({"schema_version":1,"seed_hash":"ff","verified":false,"verification_status":"probe_failed","state_version":3})",
                   "application/json");
               return;
             }
             Res.status = 201;
             Res.set_content(
                 R"({"schema_version":1,"seed_hash":"559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd","verified":true,"verification_status":"verified","edge_bitmap":[10],"novel_edges":[10],"newly_active_frontiers":["f1"],"state_version":4})",
                 "application/json");
           });
  Srv.Post("/v2/coverage/report",
           [](const httplib::Request &, httplib::Response &Res) {
             Res.set_content(
                 R"({"schema_version":1,"acknowledged":true,"state_version":4})",
                 "application/json");
           });
  Srv.Get("/v2/dictionary", [](const httplib::Request &, httplib::Response &Res) {
    Res.set_content(
        R"({"schema_version":1,"model_id":"model-1","tokens":["edge_10","edge_11","const_42"]})",
        "application/json");
  });

  int Port = Srv.bind_to_any_port("127.0.0.1");
  if (Port <= 0) {
    fprintf(stderr, "mock analyzer bind failed\n");
    return 2;
  }
  std::thread Listener([&] { Srv.listen_after_bind(); });
  setenv("ORCHESTRA_URL", ("http://127.0.0.1:" + std::to_string(Port)).c_str(), 1);

  // --- V2 client surface.
  Check(OrchestraEnabled(), "OrchestraEnabled reports ORCHESTRA_URL");
  Check(OrchestraHealth(), "GET /v2/health returns ok");
  auto State = OrchestraGetState();
  Check(State && State->ModelId == "model-1" && State->StateVersion == 4 &&
            State->FrontierCount == 2 && State->ActiveCount == 1 &&
            State->CoverageSize == 1024,
        "GET /v2/state parses");
  auto Recs = OrchestraGetActiveFrontiers();
  Check(Recs && Recs->StateVersion == 4 && Recs->Frontiers.size() == 1 &&
            Recs->Frontiers[0].FrontierKey == "f1" &&
            Recs->Frontiers[0].TrueEdgeId == 10 &&
            Recs->Frontiers[0].UncoveredEdgeId == 11 &&
            Recs->Frontiers[0].Score > 0.5 &&
            Recs->Frontiers[0].RecommendedSeeds.size() == 1 &&
            Recs->Frontiers[0].RecommendedSeeds[0] == "seed-hash-1" &&
            Recs->Frontiers[0].DictionaryTokens.size() == 2,
        "GET /v2/frontiers/active parses");
  auto Dict = OrchestraGetDictionary();
  Check(Dict && Dict->ModelId == "model-1" && Dict->Tokens.size() == 3 &&
            Dict->Tokens[2] == "const_42",
        "GET /v2/dictionary parses");

  // --- corpus/add inline bytes: base64 + hint on the wire.
  std::vector<uint8_t> Seed = {'A'};
  std::vector<uint32_t> Hint = {10, 20, 30, 40};
  auto Added = OrchestraAddCorpusData("libfuzzer", "7", "parent-hash", Seed, Hint);
  Check(Added && Added->Verified &&
            Added->VerificationStatus == "verified" &&
            Added->SeedHash.size() == 64,
        "corpus/add inline bytes verified");
  Check(LastCorpusBody.find("\"seed_data\":\"QQ==\"") != std::string::npos &&
            LastCorpusBody.find("\"fuzzer_id\":\"libfuzzer\"") != std::string::npos &&
            LastCorpusBody.find("\"job_id\":\"7\"") != std::string::npos &&
            LastCorpusBody.find("\"parent_seed_hash\":\"parent-hash\"") !=
                std::string::npos &&
            LastCorpusBody.find("\"hint_bitmap\":[10,20,30,40]") !=
                std::string::npos,
        "corpus/add wire format (base64 seed, hint bitmap)");

  // --- probe failure propagates: keep local bitmap for this seed.
  ProbeFail = true;
  auto Failed = OrchestraAddCorpusPath("libfuzzer", "7", "", "/seeds/whatever", {});
  Check(Failed && !Failed->Verified &&
            Failed->VerificationStatus == "probe_failed",
        "probe_failed propagates via shared path");
  ProbeFail = false;

  // --- coverage report ack.
  Check(OrchestraReportCoverage("afl", "7", Hint, {"f1"}, {"f1"}),
        "POST /v2/coverage/report acknowledged");

  // --- deprecated V1-signature shim.
  Check(Ready(), "shim Ready() delegates to /v2/health");
  auto Peek = PeekResult();
  Check(Peek && Peek->ConstraintGroup.GroupId == "f1" &&
            Peek->ConstraintGroup.LeafFunction == "f1" &&
            Peek->ConstraintGroup.Importance > 0.0,
        "shim PeekResult() maps first frontier");
  Check(Peek && !Peek->DictContent.empty() &&
            Peek->DictContent.find("token3=\"const_42\"") != std::string::npos,
        "shim PeekResult() emits libFuzzer dict entries");

  std::string SeedDir = (fs::temp_directory_path() / "orchestra-client-test").string();
  fs::remove_all(SeedDir);
  fs::create_directories(SeedDir);
  std::ofstream(SeedDir + "/seedA.bin") << "A";
  std::ofstream(SeedDir + "/seedB.bin") << "B";
  ReportCorpus("afl", 9, 300, "begin", {SeedDir});
  Check(CorpusCalls == 3 + 1 && // 3 prior calls + 2 files
            LastCorpusBody.find("\"seed_path\":\"" + SeedDir + "/seedB.bin\"") !=
                std::string::npos,
        "shim ReportCorpus() posts seed_path per file");
  Log("PassedMinutes 1, Strategy 1"); // engine-local; must not crash

  // --- connection failure: soft-fail semantics.
  Srv.stop();
  Listener.join();
  Check(!OrchestraHealth(), "health fails after server stop");
  Check(OrchestraGetState() == nullptr, "state returns nullptr on connection failure");
  auto Dead = OrchestraAddCorpusData("libfuzzer", "7", "", Seed, {});
  Check(Dead == nullptr, "corpus/add returns nullptr on connection failure");
  Check(!OrchestraReportCoverage("afl", "7", {}, {}, {}),
        "coverage/report fails soft after server stop");

  fs::remove_all(SeedDir);
  if (Failures) {
    fprintf(stderr, "FAILED: %d check(s) failed\n", Failures);
    return 1;
  }
  printf("ALL CHECKS PASSED\n");
  return 0;
}
