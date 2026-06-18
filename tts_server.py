"""
Piper TTS microservice — local neural voice synthesis, zero cloud latency.

Downloads the ONNX model from HuggingFace Hub on first start (cached to
~/.cache/huggingface/hub/ for subsequent runs).

Usage:
    python tts_server.py [--host 127.0.0.1] [--port 5001]

Environment overrides:
    PIPER_MODEL_REPO   HuggingFace repo id  (default: jgkawell/jarvis)
    PIPER_MODEL_FILE   ONNX filename        (default: model.onnx)
    PIPER_CONFIG_FILE  JSON config filename (default: model.onnx.json)
    PIPER_HOST / PIPER_PORT

Endpoint:
    POST /synthesize   {"text":"…","length_scale":1.0,"volume":1.0}  →  audio/wav
    GET  /health                                                       →  {"status":"ok",…}
"""

import argparse
import asyncio
import io
import logging
import os
import wave
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import fastapi
import uvicorn
from fastapi.responses import Response
from huggingface_hub import hf_hub_download
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("piper_tts")

# ── Config ───────────────────────────────────────────────────────────────────
MODEL_REPO  = os.environ.get("PIPER_MODEL_REPO",  "jgkawell/jarvis")
MODEL_FILE  = os.environ.get("PIPER_MODEL_FILE",  "model.onnx")
CONFIG_FILE = os.environ.get("PIPER_CONFIG_FILE", "model.onnx.json")
HOST        = os.environ.get("PIPER_HOST",        "127.0.0.1")
PORT        = int(os.environ.get("PIPER_PORT",    "5001"))

# ── State ────────────────────────────────────────────────────────────────────
_voice    = None
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="piper")


# ── Lifespan: model download + load ──────────────────────────────────────────
@asynccontextmanager
async def lifespan(_app: fastapi.FastAPI):
    global _voice
    loop = asyncio.get_event_loop()

    log.info("Fetching model from HuggingFace: %s …", MODEL_REPO)
    try:
        model_path, config_path = await asyncio.gather(
            loop.run_in_executor(None, lambda: hf_hub_download(MODEL_REPO, MODEL_FILE)),
            loop.run_in_executor(None, lambda: hf_hub_download(MODEL_REPO, CONFIG_FILE)),
        )
    except Exception as exc:
        log.error("Model download failed: %s", exc)
        log.error("Set PIPER_MODEL_REPO / PIPER_MODEL_FILE to point at a valid Piper repo.")
        raise SystemExit(1) from exc

    log.info("Loading Piper voice from %s …", model_path)
    from piper.voice import PiperVoice
    _voice = await loop.run_in_executor(
        None,
        lambda: PiperVoice.load(model_path, config_path=config_path, use_cuda=False),
    )
    log.info(
        "Voice ready — sample rate %d Hz, %d speaker(s)",
        _voice.config.sample_rate,
        _voice.config.num_speakers,
    )
    yield


app = fastapi.FastAPI(title="Piper TTS", version="1.0", lifespan=lifespan)


# ── Request model ─────────────────────────────────────────────────────────────
class SynthRequest(BaseModel):
    text:         str
    length_scale: float = Field(default=1.0,  ge=0.25, le=4.0)   # <1 = faster
    volume:       float = Field(default=1.0,  ge=0.0,  le=2.0)
    speaker_id:   int   = Field(default=0,    ge=0)


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    if _voice is None:
        raise fastapi.HTTPException(503, "Voice model not loaded")
    return {
        "status":      "ok",
        "model":       MODEL_REPO,
        "sample_rate": _voice.config.sample_rate,
        "speakers":    _voice.config.num_speakers,
    }


@app.post("/synthesize")
async def synthesize(req: SynthRequest):
    if _voice is None:
        raise fastapi.HTTPException(503, "Voice model not ready")
    text = req.text.strip()[:1200]
    if not text:
        raise fastapi.HTTPException(400, "No text provided")

    loop = asyncio.get_event_loop()
    wav_bytes = await loop.run_in_executor(
        _executor, _synth_wav, text, req.length_scale, req.volume, req.speaker_id
    )
    return Response(
        content=wav_bytes,
        media_type="audio/wav",
        headers={"Cache-Control": "no-store"},
    )


def _synth_wav(text: str, length_scale: float, volume: float, speaker_id: int) -> bytes:
    from piper.config import SynthesisConfig

    syn_config = SynthesisConfig(
        length_scale=length_scale,
        volume=volume,
        speaker_id=speaker_id if _voice.config.num_speakers > 1 else None,
    )

    chunks = list(_voice.synthesize(text, syn_config=syn_config))
    if not chunks:
        return b""

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(chunks[0].sample_channels)
        wf.setsampwidth(chunks[0].sample_width)
        wf.setframerate(chunks[0].sample_rate)
        for chunk in chunks:
            wf.writeframes(chunk.audio_int16_bytes)

    return buf.getvalue()


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Piper TTS microservice")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
