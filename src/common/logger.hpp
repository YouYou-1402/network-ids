#pragma once
#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <sstream>

class Logger {
public:
    enum class Level { DBG = 0, INFO = 1, WARN = 2, ERR = 3 };

    static Logger& instance() {
        static Logger inst;
        return inst;
    }

    void setLevel(Level level)      { min_level_ = level; }
    void setLogFile(const std::string& path);

    void log(Level level, const std::string& msg);

    void debug(const std::string& msg) { log(Level::DBG, msg); }
    void info (const std::string& msg) { log(Level::INFO,  msg); }
    void warn (const std::string& msg) { log(Level::WARN,  msg); }
    void error(const std::string& msg) { log(Level::ERR, msg); }

private:
    Logger() = default;
    std::string currentTimestamp() const;
    std::string levelToString(Level l) const;

    std::ofstream log_file_;
    std::mutex    mutex_;
    Level         min_level_ = Level::INFO;
    bool          file_open_ = false;
};

#define LOG_DEBUG(msg) Logger::instance().debug(msg)
#define LOG_INFO(msg)  Logger::instance().info(msg)
#define LOG_WARN(msg)  Logger::instance().warn(msg)
#define LOG_ERROR(msg) Logger::instance().error(msg)
