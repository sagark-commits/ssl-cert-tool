"""Procedural anti-aliased shapes as Tk PhotoImages (no Pillow needed).

Tk draws crisp rectangles but has no rounded corners or gradients. These helpers compute the
pixels once (signed-distance-field edge for smooth corners) and cache them, so buttons,
pills and glows look modern while the app stays dependency-free.
"""
from __future__ import annotations

import math
import tkinter as tk
from typing import Dict, Optional, Tuple

RGB = Tuple[int, int, int]
_CACHE: Dict[tuple, tk.PhotoImage] = {}


def hex_to_rgb(color: str) -> RGB:
    color = color.lstrip("#")
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def rgb_to_hex(rgb: RGB) -> str:
    return "#%02x%02x%02x" % tuple(max(0, min(255, int(round(c)))) for c in rgb)


def mix(a: str, b: str, t: float) -> str:
    """Blend colour `a` toward `b` by t (0..1)."""
    ra, rb = hex_to_rgb(a), hex_to_rgb(b)
    return rgb_to_hex(tuple(ra[i] + (rb[i] - ra[i]) * t for i in range(3)))  # type: ignore[arg-type]


def _blend(top: RGB, bottom: RGB, alpha: float) -> RGB:
    return (
        bottom[0] + (top[0] - bottom[0]) * alpha,
        bottom[1] + (top[1] - bottom[1]) * alpha,
        bottom[2] + (top[2] - bottom[2]) * alpha,
    )


def _coverage(px: float, py: float, w: int, h: int, r: float, inset: float = 0.0) -> float:
    """Pixel coverage (0..1) of a rounded rectangle, inset by `inset` pixels."""
    hx, hy = w / 2.0, h / 2.0
    rr = max(0.0, r - inset)
    qx = abs(px - hx) - (hx - inset - rr)
    qy = abs(py - hy) - (hy - inset - rr)
    d = math.hypot(max(qx, 0.0), max(qy, 0.0)) + min(max(qx, qy), 0.0) - rr
    return min(1.0, max(0.0, 0.5 - d))


def render_round(
    master: tk.Misc,
    width: int,
    height: int,
    radius: float,
    fill1: str,
    fill2: Optional[str],
    bg: str,
    *,
    vertical: bool = False,
    border: Optional[str] = None,
    border_width: float = 1.0,
) -> tk.PhotoImage:
    """A rounded rectangle filled with a gradient (fill1 -> fill2), blended onto `bg`."""
    width, height = max(2, int(width)), max(2, int(height))
    key = ("round", width, height, round(radius, 1), fill1, fill2, bg, vertical, border, border_width, id(master.winfo_toplevel()))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    radius = min(radius, width / 2.0, height / 2.0)
    c1 = hex_to_rgb(fill1)
    c2 = hex_to_rgb(fill2 or fill1)
    bgc = hex_to_rgb(bg)
    bc = hex_to_rgb(border) if border else None
    rows = []
    for y in range(height):
        row = []
        for x in range(width):
            outer = _coverage(x + 0.5, y + 0.5, width, height, radius)
            if outer <= 0.0:
                row.append(bg)
                continue
            t = (y / (height - 1)) if vertical else (x / (width - 1))
            fill = (c1[0] + (c2[0] - c1[0]) * t, c1[1] + (c2[1] - c1[1]) * t, c1[2] + (c2[2] - c1[2]) * t)
            if bc is not None:
                inner = _coverage(x + 0.5, y + 0.5, width, height, radius, inset=border_width)
                fill = _blend(fill, bc, inner)
            row.append(rgb_to_hex(_blend(fill, bgc, outer)))
        rows.append("{" + " ".join(row) + "}")
    image = tk.PhotoImage(master=master, width=width, height=height)
    image.put(" ".join(rows), to=(0, 0))
    _CACHE[key] = image
    return image


def render_glow(master: tk.Misc, width: int, height: int, color: str, bg: str) -> tk.PhotoImage:
    """A soft horizontal highlight (bg -> color -> bg): the moving part of a progress shimmer."""
    key = ("glow", width, height, color, bg, id(master.winfo_toplevel()))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    row = []
    for x in range(width):
        t = 1.0 - abs(2.0 * x / max(1, width - 1) - 1.0)
        row.append(mix(bg, color, t ** 1.4))
    line = "{" + " ".join(row) + "}"
    image = tk.PhotoImage(master=master, width=width, height=height)
    image.put(" ".join([line] * height), to=(0, 0))
    _CACHE[key] = image
    return image


def render_gradient_bar(master: tk.Misc, width: int, height: int, c1: str, c2: str, c3: Optional[str] = None) -> tk.PhotoImage:
    """A horizontal 2- or 3-stop gradient strip (header underline, accents)."""
    key = ("bar", width, height, c1, c2, c3, id(master.winfo_toplevel()))
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    row = []
    for x in range(width):
        t = x / max(1, width - 1)
        if c3 is None:
            row.append(mix(c1, c2, t))
        else:
            row.append(mix(c1, c2, t * 2) if t < 0.5 else mix(c2, c3, (t - 0.5) * 2))
    line = "{" + " ".join(row) + "}"
    image = tk.PhotoImage(master=master, width=width, height=height)
    image.put(" ".join([line] * height), to=(0, 0))
    _CACHE[key] = image
    return image


def clear_cache() -> None:
    _CACHE.clear()
