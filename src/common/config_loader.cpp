// =============================================================================
//  src/common/config_loader.cpp
//
//  Thay đổi so với phiên bản cũ:
//    [XÓA] Block parse "layer2"  — dead code
//    [ĐỔI] Section "ml" parse vào AppConfig::ml (type MLConfig)
// =============================================================================

#include "config_loader.hpp"
#include "logger.hpp"
#include <fstream>
#include <stdexcept>
#include <nlohmann/json.hpp>
#include <filesystem>

using json = nlohmann::json;

AppConfig ConfigLoader::cfg_;
bool      ConfigLoader::loaded_ = false;

template<typename T>
static T jget(const json& j, const std::string& key, T def) {
    if (j.contains(key) && !j[key].is_null())
        return j[key].get<T>();
    return def;
}

AppConfig ConfigLoader::load(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open())
        throw std::runtime_error("ConfigLoader: cannot open '" + path + "'");

    json root;
    try { f >> root; }
    catch (const json::parse_error& e) {
        throw std::runtime_error(
            std::string("ConfigLoader: JSON parse error: ") + e.what());
    }

    AppConfig c;

    // ── system ────────────────────────────────────────────────────────────
    if (root.contains("system")) {
        const auto& s = root["system"];
        c.system.num_workers           = jget(s, "num_workers",           4);
        c.system.max_flows             = jget(s, "max_flows",             10000);
        c.system.flow_idle_timeout_sec = jget(s, "flow_idle_timeout_sec", 300.0);
        c.system.log_file              = jget(s, "log_file",
                                              std::string("logs/system.log"));
        c.system.alert_log_file        = jget(s, "alert_log_file",
                                              std::string("logs/alert.log"));
        c.system.log_level             = jget(s, "log_level",
                                              std::string("INFO"));
    }

    // ── engine ────────────────────────────────────────────────────────────
    if (root.contains("engine")) {
        const auto& e = root["engine"];
        c.detection_enabled = jget(e, "detection_enabled", true);
        c.ml_enabled        = jget(e, "ml_enabled",        false);
    }

    // ── capture ───────────────────────────────────────────────────────────
    if (root.contains("capture")) {
        const auto& cap = root["capture"];
        c.capture.interface      = jget(cap, "interface",
                                        std::string("eth0"));
        c.capture.bpf_filter     = jget(cap, "bpf_filter",
                                        std::string("tcp or udp"));
        c.capture.snaplen        = jget(cap, "snaplen",        (uint32_t)65535);
        c.capture.promiscuous    = jget(cap, "promiscuous",    true);
        c.capture.ring_buffer_mb = jget(cap, "ring_buffer_mb", (uint32_t)64);
    }

    // ── token_bucket ──────────────────────────────────────────────────────
    if (root.contains("token_bucket")) {
        const auto& tb = root["token_bucket"];
        auto parseBucket = [&](const std::string& key,
                                BucketCfg& out,
                                double def_cap, double def_rate) {
            if (tb.contains(key)) {
                out.capacity    = jget(tb[key], "capacity",    def_cap);
                out.refill_rate = jget(tb[key], "refill_rate", def_rate);
            } else {
                out.capacity    = def_cap;
                out.refill_rate = def_rate;
            }
        };
        parseBucket("syn",  c.token_bucket.syn,   200.0,  20.0);
        parseBucket("udp",  c.token_bucket.udp,  2000.0, 500.0);
        parseBucket("icmp", c.token_bucket.icmp,   50.0,   5.0);
    }

    // ── thresholds ────────────────────────────────────────────────────────
    if (root.contains("thresholds")) {
        const auto& t = root["thresholds"];
        auto& th = c.thresholds;
        th.flood_ratio               = jget(t, "flood_ratio",               0.5);
        th.min_pkt_before_flood      = jget(t, "min_pkt_before_flood",      (uint64_t)20);
        th.syn_no_complete           = jget(t, "syn_no_complete",           (uint32_t)50);
        th.http_flood_req_per_window = jget(t, "http_flood_req_per_window", (uint64_t)200);
        th.behavior_window_sec       = jget(t, "behavior_window_sec",       10.0);
        th.port_scan_ports           = jget(t, "port_scan_ports",           (uint32_t)20);
        th.port_scan_syn_no_ack_min  = jget(t, "port_scan_syn_no_ack_min",  (uint32_t)25);
        th.dist_scan_src_threshold   = jget(t, "dist_scan_src_threshold",   (uint32_t)10);
        th.ip_tracker_window_sec     = jget(t, "ip_tracker_window_sec",     30.0);
        th.ip_tracker_idle_cleanup   = jget(t, "ip_tracker_idle_cleanup",   60.0);
        th.scan_idle_reset_sec       = jget(t, "scan_idle_reset_sec",       300.0);
        th.max_tracked_ip            = jget(t, "max_tracked_ip",            (size_t)65536);
        th.global_syn_threshold      = jget(t, "global_syn_threshold",      (uint64_t)2000);
        th.dst_syn_ratio_min_pkt     = jget(t, "dst_syn_ratio_min_pkt",     (uint64_t)100);
        th.dst_syn_ack_ratio         = jget(t, "dst_syn_ack_ratio",         10.0);
    }

    // ── signatures (thresholds — giữ backward compat) ────────────────────────
    if (root.contains("thresholds")) {
        const auto& t = root["thresholds"];
        c.signatures.flood_ratio              = jget(t, "flood_ratio",              0.5);
        c.signatures.port_scan_ports          = jget(t, "port_scan_ports",          (uint32_t)20);
        c.signatures.port_scan_syn_no_ack_min = jget(t, "port_scan_syn_no_ack_min", (uint32_t)25);
        c.signatures.min_pkt_before_flood     = jget(t, "min_pkt_before_flood",     (uint64_t)20);
    }

    // ── rules_file → load rules.json ─────────────────────────────────────────
    if (root.contains("rules_file")) {
        c.signatures.rules_file = root["rules_file"].get<std::string>();
    } else {
        // Default: cùng thư mục với config.json
        c.signatures.rules_file =
            std::filesystem::path(path).parent_path() / "rules.json";
    }

    // Load rules.json nếu tồn tại
    if (!c.signatures.rules_file.empty()) {
        std::ifstream rf(c.signatures.rules_file);
        if (rf.is_open()) {
            json rules_root;
            try {
                rf >> rules_root;

                // ── "signatures" array ────────────────────────────────────────
                if (rules_root.contains("signatures") &&
                    rules_root["signatures"].is_array())
                {
                    for (const auto& s : rules_root["signatures"]) {
                        SignatureRule sr;
                        sr.id      = jget(s, "id",      std::string(""));
                        sr.name    = jget(s, "name",    std::string(""));
                        sr.pattern = jget(s, "pattern", std::string(""));
                        sr.threat  = jget(s, "threat",  std::string("SLOW_DDOS"));
                        sr.action  = jget(s, "action",  std::string("ALERT"));
                        if (!sr.pattern.empty())
                            c.signatures.sig_rules.push_back(std::move(sr));
                    }
                    LOG_INFO("ConfigLoader: loaded "
                            + std::to_string(c.signatures.sig_rules.size())
                            + " signature rules from "
                            + c.signatures.rules_file);
                }

                // ── "rules" array ─────────────────────────────────────────────
                if (rules_root.contains("rules") &&
                    rules_root["rules"].is_array())
                {
                    for (const auto& r : rules_root["rules"]) {
                        BehaviorRule br;
                        br.id        = jget(r, "id",        std::string(""));
                        br.name      = jget(r, "name",      std::string(""));
                        br.condition = jget(r, "condition", std::string(""));
                        br.threat    = jget(r, "threat",    std::string("OTHER_ATTACK"));
                        br.action    = jget(r, "action",    std::string("ALERT"));
                        if (!br.condition.empty())
                            c.signatures.behavior_rules.push_back(std::move(br));
                    }
                    LOG_INFO("ConfigLoader: loaded "
                            + std::to_string(c.signatures.behavior_rules.size())
                            + " behavior rules from "
                            + c.signatures.rules_file);
                }

            } catch (const json::parse_error& e) {
                LOG_ERROR("ConfigLoader: failed to parse rules file '"
                        + c.signatures.rules_file + "': " + e.what());
            }
        } else {
            LOG_WARN("ConfigLoader: rules file not found: "
                    + c.signatures.rules_file);
        }
    }

    // ── protocol_anomaly ──────────────────────────────────────────────────
    if (root.contains("protocol_anomaly")) {
        const auto& pa  = root["protocol_anomaly"];
        auto&       out = c.protocol_anomaly;
        out.http_header_timeout_sec    = jget(pa, "http_header_timeout_sec",    30.0);
        out.min_bytes_per_sec          = jget(pa, "min_bytes_per_sec",          50.0);
        out.max_concurrent_conn        = jget(pa, "max_concurrent_conn",        (uint32_t)50);
        out.slowloris_conn_min         = jget(pa, "slowloris_conn_min",         (uint32_t)30);
        out.slow_post_duration_min_sec = jget(pa, "slow_post_duration_min_sec", 60.0);
        out.win_zero_count_threshold   = jget(pa, "win_zero_count_threshold",   (uint32_t)5);
        if (pa.contains("http_ports") && pa["http_ports"].is_array())
            for (auto& p : pa["http_ports"])
                out.http_ports.push_back(p.get<uint16_t>());
    }
    if (c.protocol_anomaly.http_ports.empty())
        c.protocol_anomaly.http_ports = {80, 8080};

    // ── media_ports ───────────────────────────────────────────────────────
    if (root.contains("media_ports")) {
        const auto& mp = root["media_ports"];
        auto parsePortList = [&](const std::string& key) -> std::vector<uint16_t> {
            std::vector<uint16_t> ports;
            if (mp.contains(key) && mp[key].is_array())
                for (auto& p : mp[key])
                    ports.push_back(p.get<uint16_t>());
            return ports;
        };
        c.media_ports.quic = parsePortList("quic");
        c.media_ports.stun = parsePortList("stun");
        if (mp.contains("rtp_heuristic")) {
            const auto& rtp = mp["rtp_heuristic"];
            c.media_ports.rtp_heuristic.enabled      = jget(rtp, "enabled",      true);
            c.media_ports.rtp_heuristic.min_pkt_size = jget(rtp, "min_pkt_size", (uint32_t)28);
            c.media_ports.rtp_heuristic.max_pkt_size = jget(rtp, "max_pkt_size", (uint32_t)1400);
        }
    }

    // ── ml ────────────────────────────────────────────────────────────────
    //  NOTE: AppConfig::ml là MLConfig (không phải MLCfg cũ).
    //  KHÔNG còn block "layer2" — đã xóa (dead code).
    if (root.contains("ml")) {
        const auto& m = root["ml"];

        // Models
        c.ml.xgb_model_path = jget(m, "xgb_model_path", std::string(""));
        c.ml.ae_model_path  = jget(m, "ae_model_path",  std::string(""));

        // Scalers
        c.ml.scaler_path        = jget(m, "scaler_path",        std::string(""));
        c.ml.scaler_nslkdd_path = jget(m, "scaler_nslkdd_path", std::string(""));

        // Meta
        c.ml.ae_meta_path = jget(m, "ae_meta_path", std::string(""));

        // Thresholds — ae_threshold default 0.099726 (khớp Python)
        c.ml.xgb_threshold     = jget(m, "xgb_threshold",     0.50f);
        c.ml.ae_threshold      = jget(m, "ae_threshold",      0.099726f);
        c.ml.ae_high_threshold = jget(m, "ae_high_threshold", 0.85f);
        c.ml.min_confidence    = jget(m, "min_confidence",    0.60f);

        // Weights
        c.ml.xgb_weight = jget(m, "xgb_weight", 0.65f);
        c.ml.ae_weight  = jget(m, "ae_weight",   0.35f);

        // Misc
        c.ml.alert_cooldown_sec = jget(m, "alert_cooldown_sec", 1.0f);
    }

    cfg_    = c;        // ← lưu vào static member
    loaded_ = true;
    return c;
}

// ─── get() ────────────────────────────────────────────────────────────────────
const AppConfig& ConfigLoader::get() {
    if (!loaded_)
        throw std::runtime_error("ConfigLoader::get() called before load()");
    return cfg_;
}
