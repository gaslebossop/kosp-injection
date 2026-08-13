from PIL import Image
import os

os.makedirs("icons", exist_ok=True)

SIZE = 256
PAD = 26  # marge autour de la seringue dans le cadre

src = Image.open("icons/source.png").convert("RGBA")

# Rend le blanc transparent (fond uni du PNG source) pour ne garder que
# la seringue, puis recadre sur son contour reel.
datas = src.getdata()
new_data = []
for r, g, b, a in datas:
    if r > 245 and g > 245 and b > 245:
        new_data.append((r, g, b, 0))
    else:
        new_data.append((r, g, b, a))
src.putdata(new_data)
bbox = src.getbbox()
src = src.crop(bbox)

# Redimensionne pour tenir dans le cadre avec la marge, en conservant le
# ratio (la seringue est en diagonale, donc plus large que haute).
inner = SIZE - 2 * PAD
scale = min(inner / src.width, inner / src.height)
resized = src.resize((int(src.width * scale), int(src.height * scale)), Image.LANCZOS)

# Fond arrondi presque noir (identique au reste de la DA de l'app) avec
# la seringue centree dessus.
bg = Image.new("RGBA", (SIZE, SIZE), (10, 10, 10, 255))
mask = Image.new("L", (SIZE, SIZE), 0)
from PIL import ImageDraw
ImageDraw.Draw(mask).rounded_rectangle([0, 0, SIZE, SIZE], radius=60, fill=255)
rounded_bg = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
rounded_bg.paste(bg, (0, 0), mask)

offset = ((SIZE - resized.width) // 2, (SIZE - resized.height) // 2)
rounded_bg.paste(resized, offset, resized)

rounded_bg.save("icons/icon.png")
rounded_bg.save("icons/icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print("icone generee")
