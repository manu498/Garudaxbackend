"""Optional YOLOv8 detector. Place your trained weights at GarudaX/ai/best.pt."""
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL_CANDIDATES = [ROOT / "ai" / "best.pt", ROOT / "ai" / "road damage" / "best.pt", ROOT / "backend" / "models" / "best.pt"]
_MODEL = None
_MODEL_PATH = None
_MODEL_LOAD_ERROR = None
_LOCK = threading.Lock()  # the Flask server is multi-threaded; YOLO must load/predict one image at a time


def detect_damage(image_path, min_conf=0.25):
    with _LOCK:
        return _detect(image_path, min_conf)


def _detect(image_path, min_conf):
    global _MODEL, _MODEL_PATH, _MODEL_LOAD_ERROR
    available_model = next((p for p in MODEL_CANDIDATES if p.is_file()), None)
    if available_model is None:
        return {"available": False, "label": "AI model not added", "confidence": None,
                "message": "Place the trained YOLOv8 best.pt file in the ai folder."}
    if _MODEL is None or _MODEL_PATH != available_model:
        try:
            from ultralytics import YOLO
            _MODEL = YOLO(str(available_model))
            _MODEL_PATH = available_model
            _MODEL_LOAD_ERROR = None
        except Exception as exc:
            _MODEL_LOAD_ERROR = str(exc)
            return {"available": False, "label": "AI model could not load", "confidence": None,
                    "message": "Check that ultralytics and the trained model are installed."}
    try:
        results = _MODEL.predict(source=str(image_path), conf=min_conf, verbose=False)
        found = []
        for result in results:
            boxes = getattr(result, "boxes", None)
            if boxes is None:
                continue
            names = getattr(result, "names", getattr(_MODEL, "names", {}))
            for box in boxes:
                class_id = int(box.cls[0].item())
                confidence = float(box.conf[0].item())
                label = names.get(class_id, str(class_id)) if isinstance(names, dict) else str(class_id)
                found.append((confidence, str(label)))
        if not found:
            return {"available": True, "label": "No damage detected", "confidence": 0.0, "message": "Model ran successfully."}
        confidence, label = max(found, key=lambda item: item[0])
        return {"available": True, "label": label, "confidence": round(confidence, 4), "message": "Detection completed."}
    except Exception:
        return {"available": False, "label": "Detection failed", "confidence": None,
                "message": "The image could not be analysed by the configured model."}
