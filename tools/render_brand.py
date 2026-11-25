"""Render original, unbranded router artwork: uv run --no-project --with pillow tools/render_brand.py."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

BRAND = Path(__file__).resolve().parents[1] / "custom_components" / "virgin_hub4" / "brand"
TILE = "#263079"
CASE = "#151c4e"
ACCENT = "#8deeee"
WHITE = "#f7f9ff"


def icon(size: int) -> Image.Image:
    # Draw at 3x resolution so the curves remain crisp at catalog-thumbnail size.
    image = Image.new("RGBA", (size * 3, size * 3))
    d = ImageDraw.Draw(image)
    scale = size * 3 / 256

    def box(*coordinates: int) -> tuple[int, ...]:
        return tuple(round(c * scale) for c in coordinates)

    d.rounded_rectangle(box(12, 12, 244, 244), radius=round(47 * scale), fill=TILE)
    d.rounded_rectangle(box(68, 61, 189, 199), radius=round(35 * scale), fill=WHITE)
    d.rounded_rectangle(box(77, 70, 180, 190), radius=round(28 * scale), fill=CASE)
    # Near the top, the two shallow curves represent the Hub's illuminated ring.
    d.arc(box(83, 80, 174, 119), 1, 179, fill=ACCENT, width=round(7 * scale))
    d.arc(box(83, 80, 174, 119), 181, 359, fill="#a7b9ff", width=round(7 * scale))
    for x in (108, 128, 148):
        d.ellipse(box(x - 4, 160, x + 4, 168), fill=ACCENT if x == 128 else WHITE)
    return image.resize((size, size), Image.Resampling.LANCZOS)


def logo(scale: int, *, dark: bool) -> Image.Image:
    image = Image.new("RGBA", (576 * scale, 160 * scale))
    image.alpha_composite(icon(152 * scale), (4 * scale, 4 * scale))
    d = ImageDraw.Draw(image)
    d.text(
        (179 * scale, 65 * scale),
        "Hub 4",
        anchor="lm",
        font=ImageFont.load_default(size=49 * scale),
        fill=WHITE if dark else CASE,
    )
    d.text(
        (182 * scale, 109 * scale),
        "Cable modem & router",
        anchor="lm",
        font=ImageFont.load_default(size=24 * scale),
        fill="#bac6ff" if dark else TILE,
    )
    return image


def main() -> None:
    BRAND.mkdir(exist_ok=True)
    for scale, suffix in ((1, ""), (2, "@2x")):
        icon(256 * scale).save(BRAND / f"icon{suffix}.png", optimize=True)
        for dark in (False, True):
            name = "dark_logo" if dark else "logo"
            logo(scale, dark=dark).save(BRAND / f"{name}{suffix}.png", optimize=True)


if __name__ == "__main__":
    main()
