"""Download the repository's trained best.pt weights into the GarudaX ai folder."""
from pathlib import Path
from urllib.request import Request, urlopen
import shutil

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "ai" / "best.pt"
URL = "https://github.com/manu498/road-damage-detection-system/raw/refs/heads/main/ai/road%20damage/best.pt"
TARGET.parent.mkdir(parents=True, exist_ok=True)
if TARGET.exists() and TARGET.stat().st_size > 1_000_000:
    print(f"Model already exists: {TARGET}")
    raise SystemExit(0)
temp = TARGET.with_suffix(".pt.download")
print("Downloading the trained road-damage model (about 23 MB)...")
try:
    req = Request(URL, headers={"User-Agent": "GarudaX-setup/1.0"})
    with urlopen(req, timeout=60) as response, temp.open("wb") as out:
        shutil.copyfileobj(response, out)
    if temp.stat().st_size < 1_000_000:
        raise RuntimeError("Downloaded file is too small; the model URL may have changed.")
    with temp.open("rb") as stream:
        if stream.read(2) != b"PK":
            raise RuntimeError("The downloaded file is not a PyTorch model archive.")
    temp.replace(TARGET)
    print(f"Model saved: {TARGET}")
except Exception as exc:
    temp.unlink(missing_ok=True)
    print(f"Model download failed: {exc}")
    print("Open the best.pt file in the project GitHub repository and download the raw file manually to GarudaX/ai/best.pt.")
    raise SystemExit(1)
