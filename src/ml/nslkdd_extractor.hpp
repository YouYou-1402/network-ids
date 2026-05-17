#pragma once
#ifndef NSLKDD_EXTRACTOR_HPP
#define NSLKDD_EXTRACTOR_HPP

#include "data_queue.hpp"
#include <vector>
#include <array>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cassert>

static constexpr int NSLKDD_LOG_DIM   = 15;
static constexpr int NSLKDD_NUM_DIM   = 6;
static constexpr int NSLKDD_SCALE_DIM = NSLKDD_LOG_DIM + NSLKDD_NUM_DIM; 
static constexpr int NSLKDD_PROTO_DIM = 3;
static constexpr int NSLKDD_FLAG_DIM  = 10;
static constexpr int NSLKDD_FREQ_DIM  = 1;
static constexpr int NSLKDD_TOTAL_DIM = NSLKDD_SCALE_DIM + NSLKDD_PROTO_DIM + NSLKDD_FLAG_DIM + NSLKDD_FREQ_DIM; 


static constexpr int NSLKDD_OFFSET_LOG   = 0;
static constexpr int NSLKDD_OFFSET_NUM   = NSLKDD_LOG_DIM;                       
static constexpr int NSLKDD_OFFSET_PROTO = NSLKDD_SCALE_DIM;                    
static constexpr int NSLKDD_OFFSET_FLAG  = NSLKDD_SCALE_DIM + NSLKDD_PROTO_DIM;  
static constexpr int NSLKDD_OFFSET_FREQ  = NSLKDD_OFFSET_FLAG + NSLKDD_FLAG_DIM;

static_assert(NSLKDD_TOTAL_DIM == 35,       "Must be 35");
static_assert(NSLKDD_OFFSET_FREQ + 1 == 35, "Offset check failed");

struct NslKddScaler {
    std::array<float, NSLKDD_SCALE_DIM> center_{};
    std::array<float, NSLKDD_SCALE_DIM> scale_ {};

    bool load(const std::string& path);
    bool isLoaded() const { return loaded_; }

    std::array<float, NSLKDD_SCALE_DIM>
    transform(const std::array<float, NSLKDD_SCALE_DIM>& raw) const;

private:
    bool loaded_ = false;
};

struct NslKddFreqMap {
    bool  load  (const std::string& path);
    bool  isLoaded()                                    const { return loaded_; }
    float lookup(uint16_t dst_port, uint8_t protocol)  const;
    size_t size()                                       const { return map_.size(); }

private:
    std::unordered_map<uint32_t, float> map_;
    static constexpr float DEFAULT_FREQ = -0.01f;
    bool loaded_ = false;
};

class NslKddExtractor {
public:
    NslKddExtractor()  = default;
    ~NslKddExtractor() = default;

    NslKddExtractor(const NslKddExtractor&)            = delete;
    NslKddExtractor& operator=(const NslKddExtractor&) = delete;
    NslKddExtractor(NslKddExtractor&&)                 = default;
    NslKddExtractor& operator=(NslKddExtractor&&)      = default;

    bool loadScaler (const std::string& scaler_bin_path);
    bool loadFreqMap(const std::string& freq_map_bin_path);
    bool loadMeta   (const std::string& meta_json_path); 

    // FlowSnapshot → vector<float>(35)
    std::vector<float> extractAndScale(const FlowSnapshot& snap) const;

    bool  isReady()   const { return scaler_.isLoaded(); }
    int   inputDim()  const { return NSLKDD_TOTAL_DIM;   }
    float threshold() const { return threshold_;          }

private:
    std::array<float, NSLKDD_SCALE_DIM>
    buildScaleBlock(const FlowSnapshot& snap) const;

    static void encodeProtocol(uint8_t  protocol, std::vector<float>& vec);
    static void encodeFlag    (TcpState state,    std::vector<float>& vec);
    void        encodeService (uint16_t dst_port, uint8_t protocol,
                               std::vector<float>& vec) const;

    NslKddScaler  scaler_;
    NslKddFreqMap freq_map_;
    float         threshold_ = 0.099726f;
};

#endif // NSLKDD_EXTRACTOR_HPP
