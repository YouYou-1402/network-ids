#pragma once
// =============================================================================
//  src/ml/nslkdd_extractor.hpp
//
//  NslKddExtractor — map FlowSnapshot → vector<float>(39)
//
//  Pipeline CHÍNH XÁC khớp với Python ColumnTransformer:
//
//  preprocessor = ColumnTransformer([
//      ('num', StandardScaler(), num_cols_23),   ← 23 cols (bao gồm label-encoded proto+flag)
//      ('cat', OneHotEncoder(drop=None), ['service'])  ← 16 cols (no drop)
//  ], remainder='drop')
//
//  BƯỚC QUAN TRỌNG trước khi vào preprocessor (trong Python):
//    1. log1p(duration, src_bytes, dst_bytes, count, srv_count,
//             num_compromised, dst_host_count, dst_host_srv_count)
//    2. LabelEncoder(protocol_type): icmp=0, tcp=1, udp=2
//    3. LabelEncoder(flag): OTH=0,REJ=1,RSTO=2,RSTOS0=3,RSTR=4,
//                           S0=5,S1=6,S2=7,S3=8,SF=9,SH=10
//    4. service → label index string → OHE (16 cats, no drop)
//
//  Vector layout (39 dims):
//  ┌─────────────────────────────────────────────────────────────┐
//  │ [0]  duration              log1p(sec)  → scaled             │
//  │ [1]  protocol_type         label_enc   → scaled             │
//  │ [2]  flag                  label_enc   → scaled             │
//  │ [3]  src_bytes             log1p       → scaled             │
//  │ [4]  dst_bytes             log1p       → scaled             │
//  │ [5]  wrong_fragment        raw         → scaled             │
//  │ [6]  hot                   raw         → scaled             │
//  │ [7]  logged_in             binary      → scaled             │
//  │ [8]  num_compromised       log1p       → scaled             │
//  │ [9]  num_file_creations    raw         → scaled             │
//  │ [10] count                 log1p       → scaled             │
//  │ [11] srv_count             log1p       → scaled             │
//  │ [12] serror_rate           ratio       → scaled             │
//  │ [13] rerror_rate           ratio       → scaled             │
//  │ [14] same_srv_rate         ratio       → scaled             │
//  │ [15] diff_srv_rate         ratio       → scaled             │
//  │ [16] srv_diff_host_rate    ratio       → scaled             │
//  │ [17] dst_host_count        log1p       → scaled             │
//  │ [18] dst_host_srv_count    log1p       → scaled             │
//  │ [19] dst_host_same_srv_rate     ratio  → scaled             │
//  │ [20] dst_host_diff_srv_rate     ratio  → scaled             │
//  │ [21] dst_host_same_src_port_rate ratio → scaled             │
//  │ [22] dst_host_srv_diff_host_rate ratio → scaled             │
//  ├─────────────────────────────────────────────────────────────┤
//  │ [23] service == IRC        (label idx 0)                    │
//  │ [24] service == eco_i      (label idx 12)                   │
//  │ [25] service == efs        (label idx 14)                   │
//  │ [26] service == exec       (label idx 15)                   │
//  │ [27] service == ftp_data   (label idx 18)                   │
//  │ [28] service == gopher     (label idx 19)                   │
//  │ [29] service == harvest    (label idx 20)                   │
//  │ [30] service == http_443   (label idx 24)                   │
//  │ [31] service == courier    (label idx 4)                    │
//  │ [32] service == pop_2      (label idx 44)                   │
//  │ [33] service == private    (label idx 47)                   │
//  │ [34] service == shell      (label idx 49)                   │
//  │ [35] service == supdup     (label idx 54)                   │
//  │ [36] service == urh_i      (label idx 60)                   │
//  │ [37] service == whois      (label idx 65)                   │
//  │ [38] service == other      (fallback)                       │
//  └─────────────────────────────────────────────────────────────┘
//
//  Scaler binary format (scaler_nslkdd.bin):
//    [float32 mean × 23][float32 std × 23] = 184 bytes
// =============================================================================

#ifndef NSLKDD_EXTRACTOR_HPP
#define NSLKDD_EXTRACTOR_HPP

#include "data_queue.hpp"
#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <cassert>

// =============================================================================
//  Dimensions
// =============================================================================
static constexpr int NSLKDD_NUM_DIM   = 23;   // StandardScaler cols
static constexpr int NSLKDD_SVC_DIM   = 16;   // OHE service cols (no drop)
static constexpr int NSLKDD_TOTAL_DIM = NSLKDD_NUM_DIM + NSLKDD_SVC_DIM; // 39

static_assert(NSLKDD_TOTAL_DIM == 39, "Must be 39");

// =============================================================================
//  NslKddScaler — StandardScaler cho 23 features
//  File format: [float32 mean×23][float32 std×23] = 184 bytes
// =============================================================================
struct NslKddScaler {
    std::array<float, NSLKDD_NUM_DIM> mean_{};
    std::array<float, NSLKDD_NUM_DIM> std_ {};

    bool load(const std::string& path);
    bool isLoaded() const { return loaded_; }

    // z = clamp((x - mean) / std, -5, 5)
    std::array<float, NSLKDD_NUM_DIM>
    transform(const std::array<float, NSLKDD_NUM_DIM>& raw) const;

private:
    bool loaded_ = false;
};

// =============================================================================
//  NslKddExtractor
// =============================================================================
class NslKddExtractor {
public:
    NslKddExtractor()  = default;
    ~NslKddExtractor() = default;

    bool loadScaler(const std::string& scaler_bin_path);
    bool loadMeta  (const std::string& meta_json_path);

    // FlowSnapshot → vector<float>(39)
    std::vector<float> extractAndScale(const FlowSnapshot& snap) const;

    bool  isReady()   const { return scaler_.isLoaded(); }
    int   inputDim()  const { return NSLKDD_TOTAL_DIM;   }
    float threshold() const { return threshold_;          }

private:
    // ── Numerical block [0..22] ───────────────────────────────────────────────
    std::array<float, NSLKDD_NUM_DIM>
    buildNumerical(const FlowSnapshot& snap) const;

    // ── Service OHE block [23..38] ────────────────────────────────────────────
    static void encodeService(uint16_t dst_port, uint8_t protocol,
                               std::vector<float>& out);

    // ── Helpers ───────────────────────────────────────────────────────────────
    // protocol_type → label index: icmp=0, tcp=1, udp=2
    static float encodeProtocol(uint8_t protocol);

    // TCP state → flag label index: OTH=0,REJ=1,RSTO=2,RSTOS0=3,RSTR=4,
    //                               S0=5,S1=6,S2=7,S3=8,SF=9,SH=10
    static float encodeFlag(const FlowSnapshot& snap);

    // dst_port → service OHE column index (0..15)
    // Returns index into the 16-element OHE array
    static int serviceToOheIndex(uint16_t dst_port, uint8_t protocol);

    NslKddScaler scaler_;
    float        threshold_ = 0.099726f;
};

#endif // NSLKDD_EXTRACTOR_HPP