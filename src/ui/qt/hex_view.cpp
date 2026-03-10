//src/ui/qt/hex_view.cpp
#include "hex_view.hpp"
#include <QPainter>
#include <QScrollBar>
#include <QMouseEvent>
#include <QFontMetrics>

HexView::HexView(QWidget* parent)
    : QAbstractScrollArea(parent)
{
    font_ = QFont("Monospace", 10);
    font_.setStyleHint(QFont::TypeWriter);

    QFontMetrics fm(font_);
    char_width_  = fm.horizontalAdvance('W');
    char_height_ = fm.height() + 2;

    setStyleSheet(
        "QAbstractScrollArea { background: #0a0a14; "
        "border: 1px solid #333; }"
        "QScrollBar:vertical { background: #1a1a2e; width: 8px; }"
        "QScrollBar::handle:vertical { background: #444; "
        "border-radius: 4px; }");

    viewport()->setStyleSheet("background: #0a0a14;");
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
    painter.fillRect(viewport()->rect(), QColor("#0a0a14"));

    if (data_.empty()) {
        painter.setPen(QColor("#555555"));
        painter.drawText(viewport()->rect(),
                         Qt::AlignCenter,
                         "No data");
        return;
    }

    int scroll_y   = verticalScrollBar()->value();
    int bpr        = bytesPerRow();
    int rh         = rowHeight();
    int first_row  = scroll_y / rh;
    int visible_rows = viewport()->height() / rh + 2;

    // Layout:
    // [offset 8ch] [space 1ch] [hex 3ch*16=48ch] [space 2ch] [ascii 16ch]
    int x_offset = char_width_;
    int x_hex    = x_offset + char_width_ * 10;
    int x_ascii  = x_hex + hexColWidth() * bpr + char_width_ * 2;

    for (int row = first_row;
         row < first_row + visible_rows;
         row++) {

        int byte_start = row * bpr;
        if (byte_start >= static_cast<int>(data_.size())) break;

        int y = row * rh - scroll_y + char_height_ - 2;

        // ── Offset ────────────────────────────────────────────────────────────
        painter.setPen(QColor("#666688"));
        painter.drawText(x_offset, y,
            QString("%1").arg(byte_start, 8, 16, QChar('0')));

        // ── Hex bytes ─────────────────────────────────────────────────────────
        for (int col = 0; col < bpr; col++) {
            int byte_idx = byte_start + col;
            if (byte_idx >= static_cast<int>(data_.size())) break;

            int x = x_hex + col * hexColWidth();

            // Highlight
            bool is_highlighted =
                (highlight_start_ >= 0 &&
                 byte_idx >= highlight_start_ &&
                 byte_idx < highlight_start_ + highlight_len_);

            if (is_highlighted) {
                painter.fillRect(x - 1, y - char_height_ + 3,
                                 hexColWidth(), rh,
                                 QColor(40, 60, 100));
                painter.setPen(QColor("#88ccff"));
            } else {
                // Alternating group color (4 bytes)
                painter.setPen((col / 4) % 2 == 0
                    ? QColor("#cccccc")
                    : QColor("#aaaaaa"));
            }

            painter.drawText(x, y,
                QString("%1").arg(data_[byte_idx], 2, 16,
                                  QChar('0')).toUpper());
        }

        // ── ASCII ─────────────────────────────────────────────────────────────
        for (int col = 0; col < bpr; col++) {
            int byte_idx = byte_start + col;
            if (byte_idx >= static_cast<int>(data_.size())) break;

            uint8_t b = data_[byte_idx];
            QChar   c = (b >= 0x20 && b < 0x7F) ? QChar(b) : QChar('.');

            bool is_highlighted =
                (highlight_start_ >= 0 &&
                 byte_idx >= highlight_start_ &&
                 byte_idx < highlight_start_ + highlight_len_);

            painter.setPen(is_highlighted
                ? QColor("#88ccff")
                : (b >= 0x20 && b < 0x7F)
                    ? QColor("#88cc88")
                    : QColor("#445544"));

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
