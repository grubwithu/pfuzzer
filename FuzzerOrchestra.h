// V2 Orchestra client for pfuzzer: talks to the passive HTTP analyzer
// (/v2/* endpoints). pfuzzer is the engine execution host; Orchestra serves
// analysis results and canonical seed verification.
//
// Wire contract: schema/orchestra-v2-api.schema.json.
// Trust boundary (CONTRACTS.md §10): bitmaps reported BY this engine are
// hints; the verified bitmap returned by Orchestra is authoritative. A
// `probe_failed` or `unavailable` verification status tells the engine to
// keep its local bitmap for that seed only.
//
// All calls fail soft: on any HTTP failure they return false/nullptr and
// never crash or block fuzzing beyond the configured timeouts.
#pragma once
#ifndef FUZZER_ORCHESTRA_H
#define FUZZER_ORCHESTRA_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "httplib.h"

namespace fuzzer {

// Shared HTTP client (ORCHESTRA_URL, default localhost:8080, bounded
// timeouts). Exported for the deprecated V1-signature shim.
httplib::Client *GetOrchestraClient();

struct OrchestraState {
  std::string ModelId;
  uint64_t StateVersion = 0;
  int FrontierCount = 0;
  int ActiveCount = 0;
  int CoverageSize = 0;
};

// One priority-ordered active-frontier recommendation.
struct OrchestraFrontier {
  std::string FrontierKey;
  uint32_t TrueEdgeId = 0;
  uint32_t FalseEdgeId = 0;
  uint32_t CoveredEdgeId = 0;
  uint32_t UncoveredEdgeId = 0;
  double Starvation = 0.0;
  double Score = 0.0;
  std::vector<std::string> RecommendedSeeds; // verified seed hashes
  std::vector<std::string> DictionaryTokens;
};

struct OrchestraActiveFrontiers {
  uint64_t StateVersion = 0;
  std::vector<OrchestraFrontier> Frontiers;
};

struct OrchestraDictionary {
  std::string ModelId;
  std::vector<std::string> Tokens;
};

struct OrchestraCorpusAddResult {
  std::string SeedHash;      // authoritative SHA-256 of the measured bytes
  bool Verified = false;
  std::string VerificationStatus; // verified | probe_failed | unavailable
  bool HintDiverged = false; // engine hint disagreed beyond 5%; keep local
  double DivergenceRatio = 0.0;
};

// True when ORCHESTRA_URL is set, i.e. the V2 analyzer backend is expected.
bool OrchestraEnabled();

// GET /v2/health: proves the HTTP link works. Also the V1-signature Ready().
bool OrchestraHealth();

// GET /v2/state.
std::unique_ptr<OrchestraState> OrchestraGetState();

// GET /v2/frontiers/active.
std::unique_ptr<OrchestraActiveFrontiers> OrchestraGetActiveFrontiers();

// GET /v2/dictionary.
std::unique_ptr<OrchestraDictionary> OrchestraGetDictionary();

// POST /v2/corpus/add with inline seed bytes (base64 on the wire).
// HintBitmap is the engine observation; hint only.
std::unique_ptr<OrchestraCorpusAddResult> OrchestraAddCorpusData(
    const std::string &FuzzerId, const std::string &JobId,
    const std::string &ParentSeedHash, const std::vector<uint8_t> &SeedData,
    const std::vector<uint32_t> &HintBitmap);

// POST /v2/corpus/add referencing a seed on the shared runtime filesystem
// (colocated processes, DESIGN.md §4.6). Transport only: Orchestra reads and
// hashes the bytes it measures.
std::unique_ptr<OrchestraCorpusAddResult> OrchestraAddCorpusPath(
    const std::string &FuzzerId, const std::string &JobId,
    const std::string &ParentSeedHash, const std::string &SeedPath,
    const std::vector<uint32_t> &HintBitmap);

// POST /v2/coverage/report after a coverage interval. Observed is a hint:
// Orchestra reduces it to an edge count for capability learning.
bool OrchestraReportCoverage(
    const std::string &FuzzerId, const std::string &JobId,
    const std::vector<uint32_t> &ObservedBitmap,
    const std::vector<std::string> &AttemptedFrontiers,
    const std::vector<std::string> &CrossedFrontiers);

} // namespace fuzzer

#endif
