//  src/ml/nslkdd_extractor.cpp

#include "nslkdd_extractor.hpp"
#include "../common/logger.hpp"
#include <fstream>
#include <cmath>
#include <algorithm>
bool NslKddScaler::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        LOG_ERROR("NslKddScaler: cannot open " + path);
        return false;
    }
    f.read(reinterpret_cast<char*>(center_.data()), NSLKDD_SCALE_DIM * sizeof(float));
    f.read(reinterpret_cast<char*>(scale_.data()),  NSLKDD_SCALE_DIM * sizeof(float));
    if (!f) {
        LOG_ERROR("NslKddScaler: read failed (file too short?) " + path);
        return false;
    }
    for (int i = 0; i < NSLKDD_SCALE_DIM; ++i) {
        if (scale_[i] < 1e-9f) {
            LOG_WARN("NslKddScaler: scale[" + std::to_string(i) + "]=0, fallback 1.0");
            scale_[i] = 1.0f;
        }
    }
    loaded_ = true;
    LOG_INFO("NslKddScaler loaded: " + path + " (21 features, 168 bytes)");
    return true;
}

std::array<float, NSLKDD_SCALE_DIM>
NslKddScaler::transform(const std::array<float, NSLKDD_SCALE_DIM>& raw) const {
    std::array<float, NSLKDD_SCALE_DIM> out{};
    for (int i = 0; i < NSLKDD_SCALE_DIM; ++i) {
        float z = (raw[i] - center_[i]) / scale_[i];
        out[i]  = std::max(-5.0f, std::min(5.0f, z));
    }
    return out;
}

bool NslKddFreqMap::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        LOG_WARN("NslKddFreqMap: cannot open " + path
                 + " — dùng default freq=" + std::to_string(DEFAULT_FREQ));
        loaded_ = true;  // không fatal
        return true;
    }
    uint32_t count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(uint32_t));
    if (!f || count == 0 || count > 10000) {
        LOG_WARN("NslKddFreqMap: invalid count=" + std::to_string(count));
        loaded_ = true;
        return true;
    }
    map_.reserve(count);
    uint32_t loaded = 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint16_t port = 0; uint8_t proto = 0, pad = 0; float freq = 0.f;
        f.read(reinterpret_cast<char*>(&port),  sizeof(uint16_t));
        f.read(reinterpret_cast<char*>(&proto), sizeof(uint8_t));
        f.read(reinterpret_cast<char*>(&pad),   sizeof(uint8_t));
        f.read(reinterpret_cast<char*>(&freq),  sizeof(float));
        if (!f) break;
        const uint32_t key = (static_cast<uint32_t>(port) << 8) | proto;
        map_[key] = freq;
        ++loaded;
    }
    loaded_ = true;
    LOG_INFO("NslKddFreqMap loaded: " + path
             + " (" + std::to_string(loaded) + "/" + std::to_string(count) + " entries)");
    return true;
}

float NslKddFreqMap::lookup(uint16_t dst_port, uint8_t protocol) const {
    const uint32_t key = (static_cast<uint32_t>(dst_port) << 8) | protocol;
    auto it = map_.find(key);
    return (it != map_.end()) ? it->second : DEFAULT_FREQ;
}
bool NslKddExtractor::loadScaler (const std::string& p) { return scaler_.load(p);   }
bool NslKddExtractor::loadFreqMap(const std::string& p) { return freq_map_.load(p); }

bool NslKddExtractor::loadMeta(const std::string& path) {
    if (path.empty()) return true;
    std::ifstream f(path);
    if (!f) return true;  // không fatal

    std::string line;
    while (std::getline(f, line)) {
        const auto key_pos = line.find("\"threshold\"");
        if (key_pos == std::string::npos) continue;
        const auto colon = line.find(':', key_pos);
        if (colon == std::string::npos) continue;

        std::string val_str;
        bool in_val = false;
        for (size_t i = colon + 1; i < line.size(); ++i) {
            const char c = line[i];
            if (!in_val && (c == ' ' || c == '\t')) continue;
            if (c == ',' || c == '}' || c == '\n' || c == '\r') break;
            val_str += c;
            in_val = true;
        }
        try {
            const float parsed = std::stof(val_str);
            if (parsed > 0.f) {
                threshold_ = parsed;
                LOG_INFO("NslKddExtractor: threshold=" + std::to_string(threshold_));
            }
            return true;
        } catch (...) { continue; }
    }
    return true;
}

std::vector<float>
NslKddExtractor::extractAndScale(const FlowSnapshot& snap) const {
    if (!scaler_.isLoaded()) {
        LOG_WARN("NslKddExtractor::extractAndScale: scaler not loaded");
        return {};
    }

    std::vector<float> vec(NSLKDD_TOTAL_DIM, 0.0f);

    // Block 1: Scale [0..20]
    auto raw    = buildScaleBlock(snap);
    auto scaled = scaler_.transform(raw);
    for (int i = 0; i < NSLKDD_SCALE_DIM; ++i) vec[i] = scaled[i];

    // Block 2: Protocol OHE [21..23]
    encodeProtocol(snap.protocol, vec);

    // Block 3: Flag OHE [24..33]
    encodeFlag(snap.tcp_state, vec);

    // Block 4: Service FreqEnc [34]
    encodeService(snap.dst_port, snap.protocol, vec);

    return vec;
}

std::array<float, NSLKDD_SCALE_DIM>
NslKddExtractor::buildScaleBlock(const FlowSnapshot& snap) const {
    std::array<float, NSLKDD_SCALE_DIM> r{};
    r[0]  = std::log1p(std::max(0.0f, snap.duration_sec));
    r[1]  = std::log1p(static_cast<float>(snap.src_bytes));
    r[2]  = std::log1p(static_cast<float>(snap.dst_bytes));
    r[3]  = std::log1p(static_cast<float>(snap.wrong_fragment));
    r[4]  = std::log1p(static_cast<float>(snap.hot));
    r[5]  = std::log1p(static_cast<float>(snap.num_compromised));
    r[6]  = 0.0f;  // num_file_creations đã DROP → log1p(0) = 0
    r[7]  = std::log1p(static_cast<float>(snap.count));
    r[8]  = std::log1p(static_cast<float>(snap.srv_count));
    r[9]  = std::log1p(std::max(0.0f, std::min(1.0f, snap.rerror_rate)));
    r[10] = std::log1p(std::max(0.0f, std::min(1.0f, snap.diff_srv_rate)));
    r[11] = std::log1p(std::max(0.0f, std::min(1.0f, snap.srv_diff_host_rate)));
    r[12] = std::log1p(std::max(0.0f, std::min(1.0f, snap.dst_host_diff_srv_rate)));
    r[13] = std::log1p(std::max(0.0f, std::min(1.0f, snap.dst_host_same_src_port_rate)));
    r[14] = std::log1p(std::max(0.0f, std::min(1.0f, snap.dst_host_srv_diff_host_rate)));
    r[15] = snap.logged_in ? 1.0f : 0.0f;
    r[16] = std::max(0.0f, std::min(1.0f, snap.serror_rate));
    r[17] = std::max(0.0f, std::min(1.0f, snap.same_srv_rate));
    r[18] = static_cast<float>(snap.dst_host_count);
    r[19] = static_cast<float>(snap.dst_host_srv_count);
    r[20] = std::max(0.0f, std::min(1.0f, snap.dst_host_same_srv_rate));

    return r;
}

void NslKddExtractor::encodeProtocol(uint8_t protocol, std::vector<float>& vec) {
    switch (protocol) {
        case 1:  vec[NSLKDD_OFFSET_PROTO + 0] = 1.0f; break;  // icmp
        case 6:  vec[NSLKDD_OFFSET_PROTO + 1] = 1.0f; break;  // tcp
        case 17: vec[NSLKDD_OFFSET_PROTO + 2] = 1.0f; break;  // udp
        default: break;  // unknown → all-zero
    }
}

void NslKddExtractor::encodeFlag(TcpState state, std::vector<float>& vec) {
    int col = -1;
    switch (state) {
        case TcpState::OTH:    col = 0; break;
        case TcpState::REJ:    col = 1; break;
        case TcpState::RSTO:   col = 2; break;
        case TcpState::RSTR:   col = 3; break;
        case TcpState::S0:     col = 4; break;
        case TcpState::S1:     col = 5; break;
        case TcpState::S2:     col = 6; break;
        case TcpState::S3:     col = 7; break;
        case TcpState::SF:     col = 8; break;
        case TcpState::SH:     col = 9; break;
        case TcpState::RSTOS0: col = -1; break;  // all-zero
        default:               col = -1; break;
    }
    if (col >= 0) vec[NSLKDD_OFFSET_FLAG + col] = 1.0f;
}

void NslKddExtractor::encodeService(uint16_t dst_port, uint8_t protocol,
                                     std::vector<float>& vec) const {
    vec[NSLKDD_OFFSET_FREQ] = freq_map_.lookup(dst_port, protocol);
}
