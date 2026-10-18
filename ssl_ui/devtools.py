"""Developer helpers: capture a Tk window to a PNG (Windows only, no Pillow)."""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path
from typing import Optional


def _png(width: int, height: int, rgb: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    stride = width * 3
    raw = b"".join(b"\x00" + rgb[y * stride:(y + 1) * stride] for y in range(height))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def capture_window(window, path: str) -> Optional[Path]:
    """Save `window` (a Tk toplevel) as PNG. Returns the path, or None if unsupported."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes

    window.update_idletasks()
    window.update()
    user32, gdi32 = ctypes.windll.user32, ctypes.windll.gdi32
    hwnd = user32.GetParent(window.winfo_id()) or window.winfo_id()
    rect = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(rect))
    width, height = rect.right - rect.left, rect.bottom - rect.top
    hdc = user32.GetWindowDC(hwnd)
    mem = gdi32.CreateCompatibleDC(hdc)
    bitmap = gdi32.CreateCompatibleBitmap(hdc, width, height)
    gdi32.SelectObject(mem, bitmap)
    user32.PrintWindow(hwnd, mem, 2)  # PW_RENDERFULLCONTENT: works even if the window is partly covered

    class BITMAPINFOHEADER(ctypes.Structure):
        _fields_ = [("biSize", wintypes.DWORD), ("biWidth", wintypes.LONG), ("biHeight", wintypes.LONG),
                    ("biPlanes", wintypes.WORD), ("biBitCount", wintypes.WORD), ("biCompression", wintypes.DWORD),
                    ("biSizeImage", wintypes.DWORD), ("biXPelsPerMeter", wintypes.LONG),
                    ("biYPelsPerMeter", wintypes.LONG), ("biClrUsed", wintypes.DWORD), ("biClrImportant", wintypes.DWORD)]

    info = BITMAPINFOHEADER()
    info.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    info.biWidth, info.biHeight, info.biPlanes, info.biBitCount = width, -height, 1, 32
    buffer = ctypes.create_string_buffer(width * height * 4)
    gdi32.GetDIBits(mem, bitmap, 0, height, buffer, ctypes.byref(info), 0)
    gdi32.DeleteObject(bitmap)
    gdi32.DeleteDC(mem)
    user32.ReleaseDC(hwnd, hdc)
    bgra = buffer.raw
    rgb = bytearray(width * height * 3)
    rgb[0::3], rgb[1::3], rgb[2::3] = bgra[2::4], bgra[1::4], bgra[0::4]
    out = Path(path)
    out.write_bytes(_png(width, height, bytes(rgb)))
    return out
