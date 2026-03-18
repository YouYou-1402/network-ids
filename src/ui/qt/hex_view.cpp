//src/ui/qt/hex_view.cpp
#include "hex_view.hpp"
#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QFontMetrics>

// ─── Palette ──────────────────────────────────────────────────────────────────
//  BG_VIEW      #ffffff    nền viewport
//  BG_HIGHLIGHT #dce8ff    highlight byte
//  FG_OFFSET    #888899    màu offset address
//  FG_HEX_A     #1a1a3e    hex group chẵn
//  FG_HEX_B     #3355cc    hex group lẻ
//  FG_HI_BYTE   #0044cc    hex/ascii khi highlighted
//  FG_ASCII_PR  #227744    ký tự printable
//  FG_ASCII_NP  #aabbaa    ký tự non-printable
//  BORDER       #d0d4e8    viền widget
// ─────────────────────────────────────────────────────────────────────────────

HexView::HexView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    font_ = QFont("Monospace", 10);
    font_.setStyleHint(QFont::TypeWriter);

    QFontMetrics fm(font_);
    char_width_  = fm.horizontalAdvance('W');
    char_height_ = fm.height() + 2;

    setStyleSheet(
        "QAbstractScrollArea {"
        "  background: #ffffff;"
        "  border: 1px solid #d0d4e8;"
        "  border-radius: 3px; }"
        "QScrollBar:vertical {"
        "  background: #f0f1f8; width: 8px;"
        "  border: none; }"
        "QScrollBar::handle:vertical {"
        "  background: #b0b8d8;"
        "  border-radius: 4px; min-height: 20px; }"
        "QScrollBar::handle:vertical:hover { background: #8898cc; }"
        "QScrollBar::add-line, QScrollBar::sub-line { height: 0; }");

    viewport()->setStyleSheet("background: #ffffff;");
}

void HexView::setData(const std::vector<uint8_t>& data) {
    data_            = data;
    highlight_start_ = -1;
    highlight_len_   = 0;
    updateScrollbar();
    viewport()->update();
}

void HexView::clearData() {
    data_.clear();
    highlight_start_ = -1;
    highlight_len_   = 0;
    verticalScrollBar()->setValue(0);
    viewport()->update();
}

void HexView::highlight(int offset, int length) {
    highlight_start_ = offset;
    highlight_len_   = length;
    viewport()->update();
}

int HexView::bytesPerRow()  const { return 16; }
int HexView::rowHeight()    const { return char_height_; }
int HexView::hexColWidth()  const { return char_width_ * 3; } // "XX "
int HexView::charColWidth() const { return char_width_; }

void HexView::updateScrollbar() {
    if (data_.empty()) {
        verticalScrollBar()->setRange(0, 0);
        return;
    }
    int rows  = (static_cast<int>(data_.size()) + bytesPerRow() - 1)
                / bytesPerRow();
    int total = rows * rowHeight();
    int vis   = viewport()->height();
    verticalScrollBar()->setRange(0, std::max(0, total - vis));
    verticalScrollBar()->setPageStep(vis);
    verticalScrollBar()->setSingleStep(rowHeight());
}

void HexView::resizeEvent(QResizeEvent* event) {
    QAbstractScrollArea::resizeEvent(event);
    updateScrollbar();
}

void HexView::paintEvent(QPaintEvent*) {
    QPainter painter(viewport());
    painter.setFont(font_);

    // ── Nền trắng ─────────────────────────────────────────────────────────────
    painter.fillRect(viewport()->rect(), QColor("#ffffff"));

    if (data_.empty()) {
        painter.setPen(QColor("#aaaacc"));
        painter.drawText(viewport()->rect(),
                         Qt::AlignCenter,
                         "No data");
        return;
    }

    int scroll_y     = verticalScrollBar()->value();
    int bpr          = bytesPerRow();
    int rh           = rowHeight();
    int first_row    = scroll_y / rh;
    int visible_rows = viewport()->height() / rh + 2;

    // Layout:
    // [offset 8ch] [space 1ch] [hex 3ch*16=48ch] [space 2ch] [ascii 16ch]
    int x_offset = char_width_;
    int x_hex    = x_offset + char_width_ * 10;
    int x_ascii  = x_hex + hexColWidth() * bpr + char_width_ * 2;

    for (int row = first_row;
         row < first_row + visible_rows;
         ++row) {

        int byte_start = row * bpr;
        if (byte_start >= static_cast<int>(data_.size())) break;

        int y = row * rh - scroll_y + char_height_ - 2;

        // ── Zebra stripe nhẹ theo hàng ────────────────────────────────────────
        if (row % 2 == 0) {
            painter.fillRect(0, y - char_height_ + 3,
                             viewport()->width(), rh,
                             QColor("#f8f9fd"));
        }

        // ── Offset ────────────────────────────────────────────────────────────
        painter.setPen(QColor("#888899"));
        painter.drawText(x_offset, y,
            QString("%1").arg(byte_start, 8, 16, QChar('0')));

        // ── Separator line giữa offset và hex ────────────────────────────────
        painter.setPen(QColor("#e0e4f0"));
        painter.drawLine(x_hex - char_width_,
                         y - char_height_ + 3,
                         x_hex - char_width_,
                         y + 2);

        // ── Hex bytes ─────────────────────────────────────────────────────────
        for (int col = 0; col < bpr; ++col) {
            int byte_idx = byte_start + col;
            if (byte_idx >= static_cast<int>(data_.size())) break;

            int x = x_hex + col * hexColWidth();

            bool is_highlighted =
                (highlight_start_ >= 0 &&
                 byte_idx >= highlight_start_ &&
                 byte_idx < highlight_start_ + highlight_len_);

            if (is_highlighted) {
                // Highlight: nền xanh pastel
                painter.fillRect(x - 1, y - char_height_ + 3,
                                 hexColWidth(), rh,
                                 QColor("#dce8ff"));
                painter.setPen(QColor("#0044cc"));
            } else {
                // Alternating group color (4 bytes)
                painter.setPen((col / 4) % 2 == 0
                    ? QColor("#1a1a3e")   // group chẵn — xanh đậm
                    : QColor("#3355cc")); // group lẻ  — xanh accent
            }

            painter.drawText(x, y,
                QString("%1").arg(data_[byte_idx], 2, 16,
                                  QChar('0')).toUpper());
        }

        // ── Separator line giữa hex và ascii ─────────────────────────────────
        painter.setPen(QColor("#e0e4f0"));
        painter.drawLine(x_ascii - char_width_,
                         y - char_height_ + 3,
                         x_ascii - char_width_,
                         y + 2);

        // ── ASCII ─────────────────────────────────────────────────────────────
        for (int col = 0; col < bpr; ++col) {
            int byte_idx = byte_start + col;
            if (byte_idx >= static_cast<int>(data_.size())) break;

            uint8_t b   = data_[byte_idx];
            QChar   c   = (b >= 0x20 && b < 0x7F) ? QChar(b) : QChar('.');
            bool printable = (b >= 0x20 && b < 0x7F);

            bool is_highlighted =
                (highlight_start_ >= 0 &&
                 byte_idx >= highlight_start_ &&
                 byte_idx < highlight_start_ + highlight_len_);

            if (is_highlighted) {
                painter.setPen(QColor("#0044cc"));
            } else if (printable) {
                painter.setPen(QColor("#227744")); // xanh lá đậm
            } else {
                painter.setPen(QColor("#bbccbb")); // non-printable — xám nhạt
            }

            painter.drawText(x_ascii + col * charColWidth(), y,
                             QString(c));
        }
    }
}

void HexView::mousePressEvent(QMouseEvent* event) {
    if (data_.empty()) return;

    int scroll_y = verticalScrollBar()->value();
    int bpr      = bytesPerRow();
    int rh       = rowHeight();
    int x_hex    = char_width_ * 11;

    int row = (event->pos().y() + scroll_y) / rh;
    int col = (event->pos().x() - x_hex)   / hexColWidth();

    if (col >= 0 && col < bpr) {
        int offset = row * bpr + col;
        if (offset < static_cast<int>(data_.size())) {
            highlight_start_ = offset;
            highlight_len_   = 1;
            viewport()->update();
            emit byteClicked(offset);
        }
    }
}
