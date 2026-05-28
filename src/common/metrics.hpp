#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <algorithm>

// Thread-safe metrics counters dùng atomic
// Được đọc bởi UI layer qua UiBridge
struct SystemMetrics {
    // ── Packet counters ───────────────────────────────────────────────────────
    std::atomic<uint64_t> packets_captured  {0};
    std::atomic<uint64_t> packets_dropped   {0};
    std::atomic<uint64_t> packets_passed    {0};
    std::atomic<uint64_t> packets_alerted   {0};

    // ── Threat counters ───────────────────────────────────────────────────────
    std::atomic<uint64_t> ddos_detected     {0};
    std::atomic<uint64_t> slow_ddos_detected{0};
    std::atomic<uint64_t> port_scan_detected{0};
    std::atomic<uint64_t> malformed_detected{0};

    // ── Performance ───────────────────────────────────────────────────────────
    std::atomic<uint64_t> active_flows      {0};
    std::atomic<uint64_t> queue_drops       {0};

    // ── Singleton ─────────────────────────────────────────────────────────────
    static SystemMetrics& instance() {
        static SystemMetrics inst;
        return inst;
    }

    void printStats() const;   // implement trong metrics.cpp
    void reset()      noexcept; // implement trong metrics.cpp

private:
    SystemMetrics() = default;
};

#define METRICS SystemMetrics::instance()

// ─── Inference timing stats ───────────────────────────────────────────────────
// Đo latency (microseconds) của từng bước inference ML.
// Thread-safe: dùng atomic, cập nhật từ MLEngine worker thread,
// đọc từ UI thread (Qt timer).
//
// Cách dùng:
//   auto t0 = InferenceStats::now();
//   /* ... run model ... */
//   INFER_STATS.recordXgb(InferenceStats::elapsedUs(t0));
// ─────────────────────────────────────────────────────────────────────────────
struct InferenceStats {
    // ── Latency tích lũy (microseconds) ──────────────────────────────────────
    std::atomic<uint64_t> xgb_total_us   {0};  // tổng thời gian XGBoost infer
    std::atomic<uint64_t> ae_total_us    {0};  // tổng thời gian Autoencoder infer
    std::atomic<uint64_t> job_total_us   {0};  // tổng thời gian processJob (bao gồm extract+infer+vote)

    // ── Min / Max latency (microseconds) ─────────────────────────────────────
    std::atomic<uint64_t> xgb_min_us     {UINT64_MAX};
    std::atomic<uint64_t> xgb_max_us     {0};
    std::atomic<uint64_t> ae_min_us      {UINT64_MAX};
    std::atomic<uint64_t> ae_max_us      {0};
    std::atomic<uint64_t> job_min_us     {UINT64_MAX};
    std::atomic<uint64_t> job_max_us     {0};

    // ── Sample counts ─────────────────────────────────────────────────────────
    std::atomic<uint64_t> xgb_count      {0};
    std::atomic<uint64_t> ae_count       {0};
    std::atomic<uint64_t> job_count      {0};

    // ── Singleton ─────────────────────────────────────────────────────────────
    static InferenceStats& instance() {
        static InferenceStats inst;
        return inst;
    }

    // ── Clock helpers ─────────────────────────────────────────────────────────
    using Clock     = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    static TimePoint now() { return Clock::now(); }

    static uint64_t elapsedUs(TimePoint t0) {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                Clock::now() - t0).count());
    }

    // ── Record helpers ────────────────────────────────────────────────────────
    void recordXgb(uint64_t us) {
        xgb_total_us.fetch_add(us, std::memory_order_relaxed);
        xgb_count   .fetch_add(1,  std::memory_order_relaxed);
        atomicMin(xgb_min_us, us);
        atomicMax(xgb_max_us, us);
    }

    void recordAe(uint64_t us) {
        ae_total_us.fetch_add(us, std::memory_order_relaxed);
        ae_count   .fetch_add(1,  std::memory_order_relaxed);
        atomicMin(ae_min_us, us);
        atomicMax(ae_max_us, us);
    }

    void recordJob(uint64_t us) {
        job_total_us.fetch_add(us, std::memory_order_relaxed);
        job_count   .fetch_add(1,  std::memory_order_relaxed);
        atomicMin(job_min_us, us);
        atomicMax(job_max_us, us);
    }

    // ── Derived: average latency (microseconds, 0 nếu chưa có sample) ────────
    uint64_t xgbAvgUs() const {
        uint64_t n = xgb_count.load(std::memory_order_relaxed);
        return n ? xgb_total_us.load(std::memory_order_relaxed) / n : 0;
    }
    uint64_t aeAvgUs() const {
        uint64_t n = ae_count.load(std::memory_order_relaxed);
        return n ? ae_total_us.load(std::memory_order_relaxed) / n : 0;
    }
    uint64_t jobAvgUs() const {
        uint64_t n = job_count.load(std::memory_order_relaxed);
        return n ? job_total_us.load(std::memory_order_relaxed) / n : 0;
    }

    // ── Throughput: jobs/sec dựa trên tổng thời gian job ─────────────────────
    // Trả về 0 nếu chưa có dữ liệu
    double jobsPerSec() const {
        uint64_t total_us = job_total_us.load(std::memory_order_relaxed);
        uint64_t n        = job_count   .load(std::memory_order_relaxed);
        if (total_us == 0 || n == 0) return 0.0;
        return static_cast<double>(n) / (static_cast<double>(total_us) * 1e-6);
    }

    void reset() noexcept {
        xgb_total_us.store(0, std::memory_order_relaxed);
        ae_total_us .store(0, std::memory_order_relaxed);
        job_total_us.store(0, std::memory_order_relaxed);
        xgb_min_us  .store(UINT64_MAX, std::memory_order_relaxed);
        xgb_max_us  .store(0, std::memory_order_relaxed);
        ae_min_us   .store(UINT64_MAX, std::memory_order_relaxed);
        ae_max_us   .store(0, std::memory_order_relaxed);
        job_min_us  .store(UINT64_MAX, std::memory_order_relaxed);
        job_max_us  .store(0, std::memory_order_relaxed);
        xgb_count   .store(0, std::memory_order_relaxed);
        ae_count    .store(0, std::memory_order_relaxed);
        job_count   .store(0, std::memory_order_relaxed);
    }

private:
    InferenceStats() = default;

    // CAS-based atomic min/max (không có std::atomic::fetch_min trước C++26)
    static void atomicMin(std::atomic<uint64_t>& a, uint64_t v) {
        uint64_t cur = a.load(std::memory_order_relaxed);
        while (v < cur && !a.compare_exchange_weak(
                cur, v, std::memory_order_relaxed)) {}
    }
    static void atomicMax(std::atomic<uint64_t>& a, uint64_t v) {
        uint64_t cur = a.load(std::memory_order_relaxed);
        while (v > cur && !a.compare_exchange_weak(
                cur, v, std::memory_order_relaxed)) {}
    }
};

#define INFER_STATS InferenceStats::instance()
