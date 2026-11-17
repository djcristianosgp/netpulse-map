"""Generates multi-resolution NetPulse 2D Windows .ico and web favicon PNG."""

from pathlib import Path
import math
from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parent.parent
ICO_PATH = ROOT / "assets" / "netpulse.ico"
PNG_PATH = ROOT / "static" / "favicon.png"


def draw_icon(size: int = 512) -> Image.Image:
    # Supersampled 512x512 canvas for crisp antialiasing
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    pad = int(size * 0.05)
    radius = int(size * 0.22)

    # Outer squircle background with radial feel
    draw.rounded_rectangle(
        [pad, pad, size - pad, size - pad],
        radius=radius,
        fill=(7, 15, 31, 255),
        outline=(34, 211, 238, 175),
        width=max(2, size // 48),
    )

    cx = cy = size / 2.0
    r_globe = size * 0.325

    # Subtle cyan glow behind globe
    glow = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    gdraw = ImageDraw.Draw(glow)
    gdraw.ellipse(
        [cx - r_globe * 1.12, cy - r_globe * 1.12, cx + r_globe * 1.12, cy + r_globe * 1.12],
        fill=(34, 211, 238, 42),
    )
    glow = glow.filter(ImageFilter.GaussianBlur(radius=size * 0.045))
    img = Image.alpha_composite(img, glow)
    draw = ImageDraw.Draw(img)

    # Globe ocean fill & rim
    draw.ellipse(
        [cx - r_globe, cy - r_globe, cx + r_globe, cy + r_globe],
        fill=(11, 27, 52, 255),
        outline=(56, 189, 248, 225),
        width=max(2, size // 64),
    )

    # Latitude & longitude graticule arcs
    grid_color = (56, 189, 248, 95)
    eq_color = (34, 211, 238, 140)
    gw = max(1, size // 128)

    # Equator and tropics
    draw.line([(cx - r_globe, cy), (cx + r_globe, cy)], fill=eq_color, width=max(2, size // 100))
    for lat_frac in (-0.48, 0.48):
        ly = cy + r_globe * lat_frac
        half_w = r_globe * math.sqrt(max(0.0, 1.0 - lat_frac * lat_frac))
        draw.line([(cx - half_w, ly), (cx + half_w, ly)], fill=grid_color, width=gw)

    # Meridians (central + two curved ellipses)
    draw.line([(cx, cy - r_globe), (cx, cy + r_globe)], fill=grid_color, width=gw)
    for rx_scale in (0.42, 0.76):
        rx = r_globe * rx_scale
        draw.ellipse([cx - rx, cy - r_globe, cx + rx, cy + r_globe], outline=grid_color, width=gw)

    # Network nodes (origin + 4 global targets)
    origin = (cx - r_globe * 0.28, cy + r_globe * 0.34)
    targets = [
        (cx - r_globe * 0.44, cy - r_globe * 0.38, (34, 211, 238, 255)),   # North America (cyan)
        (cx + r_globe * 0.22, cy - r_globe * 0.48, (56, 189, 248, 255)),   # Europe (sky)
        (cx + r_globe * 0.62, cy - r_globe * 0.12, (34, 211, 238, 255)),   # Asia (cyan)
        (cx + r_globe * 0.50, cy + r_globe * 0.46, (52, 211, 153, 255)),   # Oceania (emerald)
    ]

    # Curved quadratic bezier arcs from origin to each target
    arc_layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    adraw = ImageDraw.Draw(arc_layer)
    for tx, ty, col in targets:
        mx = (origin[0] + tx) * 0.5
        my = (origin[1] + ty) * 0.5 - r_globe * 0.28
        pts = []
        steps = 28
        for i in range(steps + 1):
            t = i / steps
            inv = 1.0 - t
            px = inv * inv * origin[0] + 2 * inv * t * mx + t * t * tx
            py = inv * inv * origin[1] + 2 * inv * t * my + t * t * ty
            pts.append((px, py))
        adraw.line(pts, fill=col, width=max(2, size // 54), joint="curve")

    arc_glow = arc_layer.filter(ImageFilter.GaussianBlur(radius=size * 0.015))
    img = Image.alpha_composite(img, arc_glow)
    img = Image.alpha_composite(img, arc_layer)
    draw = ImageDraw.Draw(img)

    # Target dots
    r_dot = size * 0.032
    for tx, ty, col in targets:
        draw.ellipse([tx - r_dot * 1.4, ty - r_dot * 1.4, tx + r_dot * 1.4, ty + r_dot * 1.4],
                     fill=(col[0], col[1], col[2], 90))
        draw.ellipse([tx - r_dot, ty - r_dot, tx + r_dot, ty + r_dot],
                     fill=col, outline=(240, 249, 255, 230), width=max(1, size // 180))

    # Origin host beacon (emerald with pulse ring)
    ox, oy = origin
    r_org = size * 0.044
    draw.ellipse([ox - r_org * 1.9, oy - r_org * 1.9, ox + r_org * 1.9, oy + r_org * 1.9],
                 outline=(52, 211, 153, 180), width=max(2, size // 128))
    draw.ellipse([ox - r_org, oy - r_org, ox + r_org, oy + r_org],
                 fill=(16, 185, 129, 255), outline=(236, 253, 245, 255), width=max(2, size // 128))

    return img


def main() -> None:
    ICO_PATH.parent.mkdir(parents=True, exist_ok=True)
    PNG_PATH.parent.mkdir(parents=True, exist_ok=True)

    master = draw_icon(512)
    master.resize((128, 128), Image.Resampling.LANCZOS).save(PNG_PATH, format="PNG")

    sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)]
    master.save(ICO_PATH, format="ICO", sizes=sizes)
    print(f"Generated {ICO_PATH} ({ICO_PATH.stat().st_size} bytes) and {PNG_PATH}")


if __name__ == "__main__":
    main()
