from PIL import Image, ImageDraw, ImageFont
import os

os.makedirs("icons", exist_ok=True)

SIZE = 256
img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
draw = ImageDraw.Draw(img)

# Fond arrondi degrade magenta, comme .brand-mark de l'UI
radius = 60
for y in range(SIZE):
    t = y / SIZE
    r = int(254 * (1 - t) + 201 * t)
    g = int(44 * (1 - t) + 31 * t)
    b = int(85 * (1 - t) + 68 * t)
    draw.line([(0, y), (SIZE, y)], fill=(r, g, b, 255))

mask = Image.new("L", (SIZE, SIZE), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, SIZE, SIZE], radius=radius, fill=255)
bg = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
bg.paste(img, (0, 0), mask)

draw = ImageDraw.Draw(bg)
try:
    font = ImageFont.truetype("segoeuib.ttf", 96)
except Exception:
    font = ImageFont.load_default()

text = "TN"
bbox = draw.textbbox((0, 0), text, font=font)
tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
draw.text(((SIZE - tw) / 2 - bbox[0], (SIZE - th) / 2 - bbox[1]), text, font=font, fill=(255, 255, 255, 255))

bg.save("icons/icon.png")
bg.save("icons/icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icone generee")
