// =============================================================================
//  src/ml/nslkdd_extractor.cpp
// =============================================================================

#include "nslkdd_extractor.hpp"
#include <fstream>
#include <cmath>
#include <algorithm>
#include <stdexcept>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
//  Service mapping: dst_port → OHE column index (0-based, 0..15)
//
//  Python pipeline:
//    1. LabelEncoder fit trên toàn bộ service strings (sorted alphabetically)
//    2. Chỉ giữ 15 indices phổ biến nhất; còn lại → 'other' (index 15)
//    3. OHE với 16 categories: [0,12,14,15,18,19,20,24,4,44,47,49,54,60,65,'other']
//       → thứ tự OHE columns theo sorted string của indices:
//         '0'→col23, '12'→col24, '14'→col25, '15'→col26, '18'→col27,
//         '19'→col28, '20'→col29, '24'→col30, '4'→col31, '44'→col32,
//         '47'→col33, '49'→col34, '54'→col35, '60'→col36, '65'→col37,
//         'other'→col38
//
//  Label index → service name (sorted alphabetically, 0-based):
//    0=IRC, 4=courier, 12=eco_i, 14=efs, 15=exec, 18=ftp_data,
//    19=gopher, 20=harvest, 24=http_443, 44=pop_2, 47=private,
//    49=shell, 54=supdup, 60=urh_i, 65=whois
//
//  Port mapping (well-known + heuristic):
// ─────────────────────────────────────────────────────────────────────────────

// OHE column offsets (relative to index 23 in the 39-dim vector)
enum ServiceOheCol : int {
    SVC_IRC       = 0,   // label idx 0  → col 23
    SVC_ECO_I     = 1,   // label idx 12 → col 24
    SVC_EFS       = 2,   // label idx 14 → col 25
    SVC_EXEC      = 3,   // label idx 15 → col 26
    SVC_FTP_DATA  = 4,   // label idx 18 → col 27
    SVC_GOPHER    = 5,   // label idx 19 → col 28
    SVC_HARVEST   = 6,   // label idx 20 → col 29
    SVC_HTTP_443  = 7,   // label idx 24 → col 30
    SVC_COURIER   = 8,   // label idx 4  → col 31
    SVC_POP2      = 9,   // label idx 44 → col 32
    SVC_PRIVATE   = 10,  // label idx 47 → col 33
    SVC_SHELL     = 11,  // label idx 49 → col 34
    SVC_SUPDUP    = 12,  // label idx 54 → col 35
    SVC_URH_I     = 13,  // label idx 60 → col 36
    SVC_WHOIS     = 14,  // label idx 65 → col 37
    SVC_OTHER     = 15,  // fallback      → col 38
};

// ─────────────────────────────────────────────────────────────────────────────
//  NslKddScaler
// ─────────────────────────────────────────────────────────────────────────────
bool NslKddScaler::load(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    // [float32 mean × 23][float32 std × 23] = 184 bytes
    f.read(reinterpret_cast<char*>(mean_.data()), NSLKDD_NUM_DIM * sizeof(float));
    f.read(reinterpret_cast<char*>(std_.data()),  NSLKDD_NUM_DIM * sizeof(float));

    if (!f) return false;

    // Sanity check: std không được = 0
    for (int i = 0; i < NSLKDD_NUM_DIM; ++i) {
        if (std_[i] < 1e-9f) std_[i] = 1.0f;  // fallback tránh div/0
    }

    loaded_ = true;
    return true;
}

std::array<float, NSLKDD_NUM_DIM>
NslKddScaler::transform(const std::array<float, NSLKDD_NUM_DIM>& raw) const {
    std::array<float, NSLKDD_NUM_DIM> out{};
    for (int i = 0; i < NSLKDD_NUM_DIM; ++i) {
        float z = (raw[i] - mean_[i]) / std_[i];
        // Clamp để tránh extreme outliers
        out[i] = std::max(-5.0f, std::min(5.0f, z));
    }
    return out;
}

// ─────────────────────────────────────────────────────────────────────────────
//  NslKddExtractor — public
// ─────────────────────────────────────────────────────────────────────────────
bool NslKddExtractor::loadScaler(const std::string& path) {
    return scaler_.load(path);
}

bool NslKddExtractor::loadMeta(const std::string& path) {
    if (path.empty()) return true;  // Không có path → dùng hardcode

    std::ifstream f(path);
    if (!f) {
        // File không tồn tại → không phải lỗi, dùng hardcode
        return true;
    }

    // Parse thủ công — tìm "ae_threshold": <value>
    // Không dùng nlohmann để tránh dependency
    std::string line;
    while (std::getline(f, line)) {
        // Tìm key "ae_threshold"
        const auto key_pos = line.find("\"ae_threshold\"");
        if (key_pos == std::string::npos) continue;

        // Tìm ':' sau key
        const auto colon = line.find(':', key_pos);
        if (colon == std::string::npos) continue;

        // Extract value string (bỏ qua spaces, dừng tại ',' hoặc '}')
        std::string val_str;
        bool in_val = false;
        for (size_t i = colon + 1; i < line.size(); ++i) {
            const char c = line[i];
            if (!in_val && (c == ' ' || c == '\t')) continue;  // skip leading space
            if (c == ',' || c == '}' || c == '\n') break;      // end of value
            val_str += c;
            in_val = true;
        }

        if (val_str.empty()) continue;

        try {
            const float parsed = std::stof(val_str);
            if (parsed > 0.0f && parsed < 1.0f) {
                threshold_ = parsed;
            }
            // Nếu parse thành công → return ngay
            return true;
        } catch (...) {
            // Parse lỗi → tiếp tục tìm dòng khác
            continue;
        }
    }

    // Không tìm thấy key → dùng hardcode, không phải lỗi
    return true;
}
std::vector<float>
NslKddExtractor::extractAndScale(const FlowSnapshot& snap) const {
    std::vector<float> vec(NSLKDD_TOTAL_DIM, 0.0f);

    // ── BLOCK 1: Numerical [0..22] ────────────────────────────────────────────
    auto raw_num = buildNumerical(snap);
    auto scaled  = scaler_.transform(raw_num);
    for (int i = 0; i < NSLKDD_NUM_DIM; ++i) {
        vec[i] = scaled[i];
    }

    // ── BLOCK 2: Service OHE [23..38] ─────────────────────────────────────────
    int svc_col = serviceToOheIndex(snap.dst_port, snap.protocol);
    vec[23 + svc_col] = 1.0f;

    return vec;
}

// ─────────────────────────────────────────────────────────────────────────────
//  buildNumerical — tạo raw 23-dim TRƯỚC khi scale
//  Thứ tự PHẢI khớp với num_cols trong Python:
//  [0]duration [1]protocol_type [2]flag [3]src_bytes [4]dst_bytes
//  [5]wrong_fragment [6]hot [7]logged_in [8]num_compromised
//  [9]num_file_creations [10]count [11]srv_count [12]serror_rate
//  [13]rerror_rate [14]same_srv_rate [15]diff_srv_rate
//  [16]srv_diff_host_rate [17]dst_host_count [18]dst_host_srv_count
//  [19]dst_host_same_srv_rate [20]dst_host_diff_srv_rate
//  [21]dst_host_same_src_port_rate [22]dst_host_srv_diff_host_rate
// ─────────────────────────────────────────────────────────────────────────────
std::array<float, NSLKDD_NUM_DIM>
NslKddExtractor::buildNumerical(const FlowSnapshot& snap) const {
    std::array<float, NSLKDD_NUM_DIM> r{};

    const auto& s = snap;

    // [0] duration — log1p(seconds)
    r[0]  = std::log1p(static_cast<float>(s.duration_sec));

    // [1] protocol_type — label encoded (icmp=0, tcp=1, udp=2), then scaled
    r[1]  = encodeProtocol(s.protocol);

    // [2] flag — TCP state label encoded (0..10), then scaled
    r[2]  = encodeFlag(s);

    // [3] src_bytes — log1p(bytes sent by src)
    r[3]  = std::log1p(static_cast<float>(s.src_bytes));

    // [4] dst_bytes — log1p(bytes sent by dst)
    r[4]  = std::log1p(static_cast<float>(s.dst_bytes));

    // [5] wrong_fragment — raw count
    r[5]  = static_cast<float>(s.wrong_fragment);

    // [6] hot — number of "hot" indicators
    r[6]  = static_cast<float>(s.hot);

    // [7] logged_in — binary (0 or 1)
    r[7]  = s.logged_in ? 1.0f : 0.0f;

    // [8] num_compromised — log1p
    r[8]  = std::log1p(static_cast<float>(s.num_compromised));

    // [9] num_file_creations — raw
    r[9]  = static_cast<float>(s.num_file_creations);

    // [10] count — log1p(connections to same host in last 2 sec)
    r[10] = std::log1p(static_cast<float>(s.count));

    // [11] srv_count — log1p(connections to same service in last 2 sec)
    r[11] = std::log1p(static_cast<float>(s.srv_count));

    // [12] serror_rate — ratio [0,1]
    r[12] = s.serror_rate;

    // [13] rerror_rate — ratio [0,1]
    r[13] = s.rerror_rate;

    // [14] same_srv_rate — ratio [0,1]
    r[14] = s.same_srv_rate;

    // [15] diff_srv_rate — ratio [0,1]
    r[15] = s.diff_srv_rate;

    // [16] srv_diff_host_rate — ratio [0,1]
    r[16] = s.srv_diff_host_rate;

    // [17] dst_host_count — log1p(connections to same dst host)
    r[17] = std::log1p(static_cast<float>(s.dst_host_count));

    // [18] dst_host_srv_count — log1p(connections to same dst host+service)
    r[18] = std::log1p(static_cast<float>(s.dst_host_srv_count));

    // [19] dst_host_same_srv_rate — ratio [0,1]
    r[19] = s.dst_host_same_srv_rate;

    // [20] dst_host_diff_srv_rate — ratio [0,1]
    r[20] = s.dst_host_diff_srv_rate;

    // [21] dst_host_same_src_port_rate — ratio [0,1]
    r[21] = s.dst_host_same_src_port_rate;

    // [22] dst_host_srv_diff_host_rate — ratio [0,1]
    r[22] = s.dst_host_srv_diff_host_rate;

    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
//  encodeProtocol
//  sklearn LabelEncoder fit(['icmp','tcp','udp']) → sorted alphabetically
// ─────────────────────────────────────────────────────────────────────────────
float NslKddExtractor::encodeProtocol(uint8_t protocol) {
    // IPPROTO_TCP=6, IPPROTO_UDP=17, IPPROTO_ICMP=1
    switch (protocol) {
        case 1:  return 0.0f;  // icmp
        case 6:  return 1.0f;  // tcp
        case 17: return 2.0f;  // udp
        default: return 1.0f;  // fallback → tcp
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  encodeFlag
//  NSL-KDD flag = TCP connection state
//  sklearn LabelEncoder sorted: OTH=0,REJ=1,RSTO=2,RSTOS0=3,RSTR=4,
//                               S0=5,S1=6,S2=7,S3=8,SF=9,SH=10
//
//  Mapping từ FlowSnapshot TCP state:
//    SF    = connection established + closed normally (SYN→ACK→FIN)
//    S0    = SYN sent, no response
//    REJ   = RST received (connection rejected)
//    RSTO  = RST from originator
//    RSTR  = RST from responder
//    S1    = SYN+SYN-ACK, no further data
//    S2    = SYN+SYN-ACK+data from orig, no FIN
//    S3    = SYN+SYN-ACK+data both sides, no FIN
//    OTH   = other/unknown
//    RSTOS0= SYN+RST
//    SH    = SYN+FIN (half-open)
// ─────────────────────────────────────────────────────────────────────────────
float NslKddExtractor::encodeFlag(const FlowSnapshot& snap) {
    // Dựa vào TCP flags trong FlowSnapshot
    // Bạn cần điều chỉnh theo cấu trúc FlowSnapshot thực tế
    switch (snap.tcp_state) {
        case TcpState::SF:     return 9.0f;
        case TcpState::S0:     return 5.0f;
        case TcpState::REJ:    return 1.0f;
        case TcpState::RSTO:   return 2.0f;
        case TcpState::RSTR:   return 4.0f;
        case TcpState::S1:     return 6.0f;
        case TcpState::S2:     return 7.0f;
        case TcpState::S3:     return 8.0f;
        case TcpState::RSTOS0: return 3.0f;
        case TcpState::SH:     return 10.0f;
        default:               return 0.0f;  // OTH
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  serviceToOheIndex
//  Trả về index trong mảng OHE 16 phần tử (0..15)
//  Dựa trên dst_port → service name → label index → OHE column
//
//  OHE column order (sorted by label index string):
//    col0=IRC(0), col1=eco_i(12), col2=efs(14), col3=exec(15),
//    col4=ftp_data(18), col5=gopher(19), col6=harvest(20),
//    col7=http_443(24), col8=courier(4), col9=pop_2(44),
//    col10=private(47), col11=shell(49), col12=supdup(54),
//    col13=urh_i(60), col14=whois(65), col15=other
// ─────────────────────────────────────────────────────────────────────────────
int NslKddExtractor::serviceToOheIndex(uint16_t dst_port, uint8_t protocol) {
    // TCP services
    if (protocol == 6) {  // TCP
        switch (dst_port) {
            case 194:  return SVC_IRC;       // IRC
            case 20:   return SVC_FTP_DATA;  // ftp_data
            case 70:   return SVC_GOPHER;    // gopher
            case 443:  return SVC_HTTP_443;  // http_443
            case 530:  return SVC_COURIER;   // courier
            case 109:  return SVC_POP2;      // pop_2
            case 514:  return SVC_SHELL;     // shell (rsh)
            case 95:   return SVC_SUPDUP;    // supdup
            case 43:   return SVC_WHOIS;     // whois
            // exec(512), efs(520), harvest(rare)
            case 512:  return SVC_EXEC;      // exec
            case 520:  return SVC_EFS;       // efs (route → efs in NSL-KDD)
            // private = high ports (>1023) không phải well-known
            default:
                if (dst_port > 1023) return SVC_PRIVATE;
                return SVC_OTHER;
        }
    }
    // UDP services
    if (protocol == 17) {  // UDP
        switch (dst_port) {
            case 7:    return SVC_ECO_I;    // echo (icmp echo in NSL-KDD)
            case 8:    return SVC_URH_I;    // urh_i
            default:
                if (dst_port > 1023) return SVC_PRIVATE;
                return SVC_OTHER;
        }
    }
    // ICMP
    if (protocol == 1) {
        return SVC_ECO_I;  // eco_i là ICMP echo request trong NSL-KDD
    }
    return SVC_OTHER;
}