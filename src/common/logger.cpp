#include "logger.hpp"

void Logger::setLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_file_.open(path, std::ios::app);
    file_open_ = log_file_.is_open();
    if (!file_open_)
        std::cerr << "[Logger] Cannot open log file: " << path << "\n";
}

void Logger::log(Level level, const std::string& msg) {
    if (level < min_level_) return;

    std::string line = currentTimestamp()
                     + " [" + levelToString(level) + "] "
                     + msg + "\n";

    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << line;
    if (file_open_)
        log_file_ << line;
}

std::string Logger::currentTimestamp() const {
    auto now     = std::chrono::system_clock::now();
    auto time_t  = std::chrono::system_clock::to_time_t(now);
    auto ms      = std::chrono::duration_cast<std::chrono::milliseconds>(
                       now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::string Logger::levelToString(Level l) const {
    switch (l) {
        case Level::DBG:  return "DEBUG";
        case Level::INFO: return "INFO ";
        case Level::WARN: return "WARN ";
        case Level::ERR:  return "ERROR";
        default:          return "?????";
    }
}

