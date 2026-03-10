cmake_minimum_required(VERSION 3.16)

project(NetworkIDS VERSION 0.1.0 LANGUAGES CXX)

# ─────────────────────────────────────────────────────────────────────────────
# C++ Standard
# ─────────────────────────────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ─────────────────────────────────────────────────────────────────────────────
# Build type default
# ─────────────────────────────────────────────────────────────────────────────
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

message(STATUS "Build type : ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")

# ─────────────────────────────────────────────────────────────────────────────
# Compiler flags
# ─────────────────────────────────────────────────────────────────────────────
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    set(CMAKE_CXX_FLAGS_DEBUG          "-g -O0 -Wall -Wextra -Wpedantic -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE        "-O2 -DNDEBUG")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Options
# ─────────────────────────────────────────────────────────────────────────────
option(BUILD_UI    "Build Qt6 GUI target"      ON)
option(BUILD_CLI   "Build headless CLI target" ON)
option(BUILD_TESTS "Build unit tests"          OFF)
option(USE_ONNX    "Enable ONNX Runtime"       OFF)

# ─────────────────────────────────────────────────────────────────────────────
# Find libpcap
# ─────────────────────────────────────────────────────────────────────────────
find_library(PCAP_LIB   NAMES pcap REQUIRED)
find_path(PCAP_INCLUDE_DIR NAMES pcap.h REQUIRED)

if(NOT PCAP_LIB)
    message(FATAL_ERROR
        "libpcap not found.\n"
        "Install: sudo apt-get install libpcap-dev")
endif()

message(STATUS "libpcap     : ${PCAP_LIB}")
message(STATUS "pcap include: ${PCAP_INCLUDE_DIR}")

# ─────────────────────────────────────────────────────────────────────────────
# Find ONNX Runtime (optional)
# ─────────────────────────────────────────────────────────────────────────────
if(USE_ONNX)
    find_path(ONNX_INCLUDE_DIR
        NAMES onnxruntime_cxx_api.h
        PATHS
            /usr/local/include/onnxruntime
            /usr/include/onnxruntime
            $ENV{ONNXRUNTIME_ROOT}/include
    )
    find_library(ONNX_LIB
        NAMES onnxruntime
        PATHS
            /usr/local/lib
            /usr/lib
            $ENV{ONNXRUNTIME_ROOT}/lib
    )

    if(ONNX_INCLUDE_DIR AND ONNX_LIB)
        message(STATUS "ONNX Runtime: ${ONNX_LIB}")
        add_compile_definitions(USE_ONNX)
    else()
        message(WARNING
            "ONNX Runtime not found — falling back to Mock models.\n"
            "Set ONNXRUNTIME_ROOT or install to /usr/local.")
        set(USE_ONNX OFF)
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Qt6
# ─────────────────────────────────────────────────────────────────────────────
if(BUILD_UI)
    find_package(Qt6
        COMPONENTS Core Widgets Charts
        REQUIRED
    )

    if(NOT Qt6_FOUND)
        message(FATAL_ERROR
            "Qt6 not found.\n"
            "Install: sudo apt-get install "
            "qt6-base-dev qt6-charts-dev libqt6charts6-dev\n"
            "Or disable: cmake -DBUILD_UI=OFF")
    endif()

    message(STATUS "Qt6 version : ${Qt6_VERSION}")

    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    set(CMAKE_AUTOUIC ON)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Source groups — theo cấu trúc thư mục mới
# ─────────────────────────────────────────────────────────────────────────────

# ── core/ — domain objects ────────────────────────────────────────────────────
set(CORE_SOURCES
    src/core/packet_info.cpp
)
set(CORE_HEADERS
    src/core/packet_info.hpp
    src/core/threat_types.hpp
)

# ── common/ — pure utilities ──────────────────────────────────────────────────
set(COMMON_SOURCES
    src/common/logger.cpp
    src/common/metrics.cpp
    src/common/config_loader.cpp
)
set(COMMON_HEADERS
    src/common/logger.hpp
    src/common/metrics.hpp
    src/common/config_loader.hpp
)

# ── capture/ — thu thập packet từ NIC ────────────────────────────────────────
set(CAPTURE_SOURCES
    src/capture/packet_capture.cpp
    src/capture/bpf_filter.cpp
    src/capture/protocol_decoder.cpp
)
set(CAPTURE_HEADERS
    src/capture/packet_capture.hpp
    src/capture/bpf_filter.hpp
    src/capture/protocol_decoder.hpp
)

# ── capture/io/ — đọc/ghi pcap file + ring buffer ────────────────────────────
set(CAPTURE_IO_SOURCES
    src/capture/io/packet_ring_buffer.cpp
    src/capture/io/pcap_reader.cpp
    src/capture/io/pcap_writer.cpp
)
set(CAPTURE_IO_HEADERS
    src/capture/io/packet_ring_buffer.hpp
    src/capture/io/pcap_reader.hpp
    src/capture/io/pcap_writer.hpp
)

# ── detection/ — IDS engine rule-based ───────────────────────────────────────
set(DETECTION_SOURCES
    src/detection/flow_table.cpp
    src/detection/signature_engine.cpp
    src/detection/behavioral_engine.cpp
    src/detection/protocol_anomaly.cpp
    src/detection/worker_thread.cpp
    src/detection/dispatcher.cpp
)
set(DETECTION_HEADERS
    src/detection/flow_state.hpp
    src/detection/flow_table.hpp
    src/detection/signature_engine.hpp
    src/detection/behavioral_engine.hpp
    src/detection/protocol_anomaly.hpp
    src/detection/worker_thread.hpp
    src/detection/dispatcher.hpp
    src/detection/action_handler.hpp
)

# ── ml/ — ML engine ──────────────────────────────────────────────────────────
set(ML_SOURCES
    src/ml/feature_extractor.cpp
    src/ml/onnx_model.cpp
    src/ml/ml_engine.cpp
    src/ml/data_queue.cpp
    src/ml/feedback_loop.cpp
)
set(ML_HEADERS
    src/ml/feature_extractor.hpp
    src/ml/onnx_model.hpp
    src/ml/ml_engine.hpp
    src/ml/data_queue.hpp
    src/ml/feedback_loop.hpp
)

# ── analysis/ — alert + stats ─────────────────────────────────────────────────
set(ANALYSIS_SOURCES
    src/analysis/alert_manager.cpp
    src/analysis/stats_collector.cpp
)
set(ANALYSIS_HEADERS
    src/analysis/alert_manager.hpp
    src/analysis/stats_collector.hpp
)

# ── ui/qt/ — Qt6 GUI ─────────────────────────────────────────────────────────
set(UI_SOURCES
    src/ui/qt/ui_bridge.cpp
    src/ui/qt/main_window.cpp
    src/ui/qt/pcap_tab.cpp
    src/ui/qt/packet_list_model.cpp
    src/ui/qt/packet_detail_tree.cpp
    src/ui/qt/hex_view.cpp
    src/ui/qt/filter_bar.cpp
    src/ui/qt/alert_panel.cpp
    src/ui/qt/metrics_widget.cpp
    src/ui/qt/traffic_chart.cpp
    src/ui/qt/capture_control_dialog.cpp
)
set(UI_HEADERS
    src/ui/qt/ui_bridge.hpp
    src/ui/qt/main_window.hpp
    src/ui/qt/pcap_tab.hpp
    src/ui/qt/packet_list_model.hpp
    src/ui/qt/packet_detail_tree.hpp
    src/ui/qt/hex_view.hpp
    src/ui/qt/filter_bar.hpp
    src/ui/qt/alert_panel.hpp
    src/ui/qt/metrics_widget.hpp
    src/ui/qt/traffic_chart.hpp
    src/ui/qt/capture_control_dialog.hpp
)

# ── Engine sources — dùng chung cho cả 2 targets ─────────────────────────────
set(ENGINE_SOURCES
    ${CORE_SOURCES}
    ${COMMON_SOURCES}
    ${CAPTURE_SOURCES}
    ${CAPTURE_IO_SOURCES}
    ${DETECTION_SOURCES}
    ${ML_SOURCES}
    ${ANALYSIS_SOURCES}
)

# ─────────────────────────────────────────────────────────────────────────────
# Helper: apply common settings
# ─────────────────────────────────────────────────────────────────────────────
function(apply_common_settings TARGET_NAME)
    target_include_directories(${TARGET_NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/src   # include "core/packet_info.hpp" etc.
        ${PCAP_INCLUDE_DIR}
    )

    target_link_libraries(${TARGET_NAME} PRIVATE
        ${PCAP_LIB}
        pthread
    )

    if(USE_ONNX AND ONNX_LIB)
        target_include_directories(${TARGET_NAME} PRIVATE ${ONNX_INCLUDE_DIR})
        target_link_libraries(${TARGET_NAME} PRIVATE ${ONNX_LIB})
    endif()

    target_compile_definitions(${TARGET_NAME} PRIVATE
        PROJECT_VERSION="${PROJECT_VERSION}"
    )

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${TARGET_NAME} PRIVATE
            -Wall -Wextra
            -Wno-unused-parameter
            -Wno-missing-field-initializers
        )
    endif()
endfunction()

# ─────────────────────────────────────────────────────────────────────────────
# Target 1: network_ids — headless CLI
# ─────────────────────────────────────────────────────────────────────────────
if(BUILD_CLI)
    add_executable(network_ids
        src/main.cpp
        ${ENGINE_SOURCES}
    )

    apply_common_settings(network_ids)

    message(STATUS "CLI target  : network_ids")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Target 2: network_ids_ui — Qt6 GUI
# ─────────────────────────────────────────────────────────────────────────────
if(BUILD_UI)
    add_executable(network_ids_ui
        src/ui_main.cpp
        ${ENGINE_SOURCES}
        ${UI_SOURCES}
        ${UI_HEADERS}   # MOC cần thấy headers có Q_OBJECT
    )

    apply_common_settings(network_ids_ui)

    target_link_libraries(network_ids_ui PRIVATE
        Qt6::Core
        Qt6::Widgets
        Qt6::Charts
    )

    target_include_directories(network_ids_ui PRIVATE
        ${Qt6Core_INCLUDE_DIRS}
        ${Qt6Widgets_INCLUDE_DIRS}
        ${Qt6Charts_INCLUDE_DIRS}
    )

    target_compile_definitions(network_ids_ui PRIVATE
        QT_NO_DEPRECATED_WARNINGS
        QT_DISABLE_DEPRECATED_BEFORE=0x060000
    )

    message(STATUS "UI target   : network_ids_ui (Qt ${Qt6_VERSION})")
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Tests (optional)
# ─────────────────────────────────────────────────────────────────────────────
if(BUILD_TESTS)
    enable_testing()
    find_package(GTest QUIET)

    if(GTest_FOUND)
        add_subdirectory(tests)
        message(STATUS "Tests       : ENABLED (GTest found)")
    else()
        message(WARNING
            "GTest not found — tests disabled.\n"
            "Install: sudo apt-get install libgtest-dev")
    endif()
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Install rules
# ─────────────────────────────────────────────────────────────────────────────
include(GNUInstallDirs)

if(BUILD_CLI)
    install(TARGETS network_ids
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(BUILD_UI)
    install(TARGETS network_ids_ui
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(DIRECTORY config/
    DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/network-ids)

install(DIRECTORY models/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/network-ids/models
    OPTIONAL)

# ─────────────────────────────────────────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────────────────────────────────────────
message(STATUS "")
message(STATUS "╔══════════════════════════════════════╗")
message(STATUS "║     NetworkIDS Build Configuration   ║")
message(STATUS "╠══════════════════════════════════════╣")
message(STATUS "║ Build type  : ${CMAKE_BUILD_TYPE}")
message(STATUS "║ C++ std     : ${CMAKE_CXX_STANDARD}")
message(STATUS "║ CLI target  : ${BUILD_CLI}")
message(STATUS "║ UI target   : ${BUILD_UI}")
message(STATUS "║ Tests       : ${BUILD_TESTS}")
message(STATUS "║ ONNX Runtime: ${USE_ONNX}")
message(STATUS "║ libpcap     : ${PCAP_LIB}")
message(STATUS "╚══════════════════════════════════════╝")
message(STATUS "")


