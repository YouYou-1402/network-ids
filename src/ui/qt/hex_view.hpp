//src/ui/qt/hex_view.hpp
#pragma once
#include <QAbstractScrollArea>
#include <QFont>
#include <vector>
#include <cstdint>

// Hex dump widget — giống Wireshark bottom pane
// Tự vẽ bằng paintEvent để tối ưu hiệu năng
class HexView : public QAbstractScrollArea {
    Q_OBJECT

public:
    explicit HexView(QWidget* parent = nullptr);

    void setData(const std::vector<uint8_t>& data);
    void clearData();

    // Highlight một byte range (ví dụ: khi click vào field trong detail tree)
    void highlight(int offset, int length);

protected:
    void paintEvent     (QPaintEvent*  event)  override;
    void resizeEvent    (QResizeEvent* event)  override;
    void mousePressEvent(QMouseEvent*  event)  override;

signals:
    void byteClicked(int offset);

private:
    void updateScrollbar();
    int  bytesPerRow()   const;
    int  rowHeight()     const;
    int  hexColWidth()   const;
    int  charColWidth()  const;

    std::vector<uint8_t> data_;
    int                  highlight_start_ = -1;
    int                  highlight_len_   = 0;

    QFont                font_;
    int                  char_width_  = 0;
    int                  char_height_ = 0;
};
