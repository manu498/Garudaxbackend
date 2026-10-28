"""Photo helpers: fingerprints for repeated-photo detection, EXIF date check and GPS distance."""
import hashlib
import math
from datetime import datetime
from io import BytesIO

from PIL import Image, ImageOps


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dhash_hex(data: bytes, size: int = 8) -> str:
    """Difference hash: similar-looking photos give hashes that differ in only a few bits,
    even after resizing, re-compression or small brightness changes."""
    with Image.open(BytesIO(data)) as img:
        img = ImageOps.exif_transpose(img).convert("L").resize((size + 1, size), Image.Resampling.LANCZOS)
        pixels = list(img.getdata())
    bits = 0
    for row in range(size):
        for col in range(size):
            left = pixels[row * (size + 1) + col]
            right = pixels[row * (size + 1) + col + 1]
            bits = (bits << 1) | (1 if left > right else 0)
    return f"{bits:0{size * size // 4}x}"


def hamming(hex_a: str, hex_b: str) -> int:
    if not hex_a or not hex_b:
        return 64
    return bin(int(hex_a, 16) ^ int(hex_b, 16)).count("1")


def exif_taken_at(data: bytes):
    """Return the photo's EXIF capture time (naive local datetime) if the camera recorded one."""
    try:
        with Image.open(BytesIO(data)) as img:
            exif = img.getexif()
            if not exif:
                return None
            value = None
            try:
                value = exif.get_ifd(0x8769).get(36867)  # DateTimeOriginal
            except Exception:
                value = None
            value = value or exif.get(306)  # DateTime
            if not value:
                return None
            return datetime.strptime(str(value).strip()[:19], "%Y:%m:%d %H:%M:%S")
    except Exception:
        return None


def distance_m(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance in metres (haversine formula)."""
    r = 6371000.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))
