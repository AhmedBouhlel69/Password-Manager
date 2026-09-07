import os
import struct
from PySide6.QtGui import (
    QImage, QPainter, QPainterPath, QColor, QLinearGradient, 
    QPen, QBrush
)
from PySide6.QtCore import Qt, QRectF, QPointF, QByteArray, QBuffer, QIODevice

def draw_securevault_icon(size: int) -> QImage:
    """Draw a high-resolution, pixel-crisp cybersecurity shield and vault lock icon."""
    image = QImage(size, size, QImage.Format_ARGB32_Premultiplied)
    image.fill(Qt.transparent)

    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)

    scale = size / 256.0

    # 1. Background Shield
    shield_path = QPainterPath()
    shield_path.moveTo(128 * scale, 18 * scale)
    shield_path.lineTo(224 * scale, 46 * scale)
    shield_path.cubicTo(224 * scale, 130 * scale, 185 * scale, 195 * scale, 128 * scale, 238 * scale)
    shield_path.cubicTo(71 * scale, 195 * scale, 32 * scale, 130 * scale, 32 * scale, 46 * scale)
    shield_path.closeSubpath()

    # Outer glow / background gradient
    shield_grad = QLinearGradient(32 * scale, 18 * scale, 224 * scale, 238 * scale)
    shield_grad.setColorAt(0.0, QColor("#1e1e2e"))
    shield_grad.setColorAt(0.5, QColor("#181825"))
    shield_grad.setColorAt(1.0, QColor("#11111b"))

    painter.setPen(Qt.NoPen)
    painter.setBrush(shield_grad)
    painter.drawPath(shield_path)

    # Neon rim border
    rim_grad = QLinearGradient(0, 0, 256 * scale, 256 * scale)
    rim_grad.setColorAt(0.0, QColor("#7aa2f7"))
    rim_grad.setColorAt(0.5, QColor("#bb9af7"))
    rim_grad.setColorAt(1.0, QColor("#2ac3de"))
    rim_pen = QPen(QBrush(rim_grad), max(2.0, 7.0 * scale))
    rim_pen.setJoinStyle(Qt.RoundJoin)
    painter.strokePath(shield_path, rim_pen)

    # 2. Vault Padlock
    # Shackle (Arch)
    shackle_pen = QPen(QColor("#7dcfff"), max(2.0, 10.0 * scale))
    shackle_pen.setCapStyle(Qt.RoundCap)
    painter.setPen(shackle_pen)
    painter.setBrush(Qt.NoBrush)
    
    shackle_rect = QRectF(98 * scale, 76 * scale, 60 * scale, 60 * scale)
    painter.drawArc(shackle_rect, 0 * 16, 180 * 16)
    painter.drawLine(QPointF(98 * scale, 106 * scale), QPointF(98 * scale, 126 * scale))
    painter.drawLine(QPointF(158 * scale, 106 * scale), QPointF(158 * scale, 126 * scale))

    # Lock Body
    body_rect = QRectF(82 * scale, 120 * scale, 92 * scale, 76 * scale)
    body_grad = QLinearGradient(82 * scale, 120 * scale, 174 * scale, 196 * scale)
    body_grad.setColorAt(0.0, QColor("#7aa2f7"))
    body_grad.setColorAt(1.0, QColor("#3d59a1"))
    
    painter.setPen(QPen(QColor("#bb9af7"), max(1.5, 2.5 * scale)))
    painter.setBrush(body_grad)
    painter.drawRoundedRect(body_rect, 10.0 * scale, 10.0 * scale)

    # Keyhole
    keyhole_path = QPainterPath()
    keyhole_path.addEllipse(QPointF(128 * scale, 150 * scale), 9 * scale, 9 * scale)
    keyhole_path.moveTo((128 - 5) * scale, 153 * scale)
    keyhole_path.lineTo((128 + 5) * scale, 153 * scale)
    keyhole_path.lineTo((128 + 7) * scale, 173 * scale)
    keyhole_path.lineTo((128 - 7) * scale, 173 * scale)
    keyhole_path.closeSubpath()

    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor("#1e1e2e"))
    painter.drawPath(keyhole_path)

    # Glowing center pip
    painter.setBrush(QColor("#7dcfff"))
    painter.drawEllipse(QPointF(128 * scale, 150 * scale), 4 * scale, 4 * scale)

    painter.end()
    return image

def image_to_png_bytes(image: QImage) -> bytes:
    ba = QByteArray()
    buffer = QBuffer(ba)
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(ba.data())

def create_ico_file(png_images: list, output_ico_path: str):
    """Write standard multi-resolution ICO file containing PNG streams."""
    count = len(png_images)
    header = struct.pack("<HHH", 0, 1, count)
    
    entries = []
    offset = 6 + count * 16
    
    data_blobs = []
    for (w, h, png_bytes) in png_images:
        size = len(png_bytes)
        b_w = 0 if w >= 256 else w
        b_h = 0 if h >= 256 else h
        entry = struct.pack("<BBBBHHII", b_w, b_h, 0, 0, 1, 32, size, offset)
        entries.append(entry)
        data_blobs.append(png_bytes)
        offset += size

    with open(output_ico_path, "wb") as f:
        f.write(header)
        for e in entries:
            f.write(e)
        for b in data_blobs:
            f.write(b)

def main():
    assets_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets")
    os.makedirs(assets_dir, exist_ok=True)

    sizes = [256, 128, 64, 48, 32, 16]
    png_images = []

    for s in sizes:
        img = draw_securevault_icon(s)
        png_data = image_to_png_bytes(img)
        png_images.append((s, s, png_data))
        if s == 256:
            png_path = os.path.join(assets_dir, "icon.png")
            with open(png_path, "wb") as f:
                f.write(png_data)
            print(f"Saved PNG icon: {png_path}")

    ico_path = os.path.join(assets_dir, "icon.ico")
    create_ico_file(png_images, ico_path)
    print(f"Saved multi-resolution ICO icon: {ico_path}")

if __name__ == "__main__":
    main()
