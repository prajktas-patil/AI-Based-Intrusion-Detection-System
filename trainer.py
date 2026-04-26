"""
trainer.py  –  Train or retrain the IsolationForest anomaly model.

Priority:
  1. KAGGLE_IDS_DATASET env var pointing to a CIC-IDS-style CSV
  2. Synthetic baseline samples (safe fallback for demo / CI)

Run:
    python trainer.py
    KAGGLE_IDS_DATASET=/path/to/CICIDS2017.csv python trainer.py
"""

from __future__ import annotations

import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from config import settings

FEATURE_COLUMNS = [
    "bytes_sent",
    "bytes_received",
    "duration_ms",
    "packet_count",
    "src_port",
    "dst_port",
]


# ─── helpers ────────────────────────────────────────────────────────────────

def _first_existing(df: pd.DataFrame, candidates: list[str], default: float = 0.0) -> pd.Series:
    lookup = {c.lower().strip(): c for c in df.columns}
    for name in candidates:
        col = lookup.get(name.lower().strip())
        if col:
            return pd.to_numeric(df[col], errors="coerce").fillna(default)
    return pd.Series(default, index=df.index, dtype=float)


def _generate_synthetic_samples(size: int = 3000) -> np.ndarray:
    rng = np.random.default_rng(seed=42)
    bytes_sent      = rng.normal(loc=900,  scale=220, size=size).clip(50, 5000)
    bytes_received  = rng.normal(loc=1300, scale=300, size=size).clip(50, 8000)
    duration_ms     = rng.normal(loc=140,  scale=60,  size=size).clip(10, 3000)
    packet_count    = rng.normal(loc=8,    scale=3,   size=size).clip(1, 100)
    src_port        = rng.integers(1024, 65535, size=size)
    dst_port        = rng.choice([53, 80, 123, 443, 587, 8080], size=size)
    return np.column_stack([bytes_sent, bytes_received, duration_ms,
                            packet_count, src_port, dst_port])


def load_kaggle_benign_samples(dataset_path: str) -> np.ndarray:
    """
    Load benign rows from a CIC-IDS-style CSV and map columns to our
    6 feature space. Handles CIC-IDS-2017, CIC-IDS-2018, and KDD-Cup99
    column naming variations.
    """
    print(f"  Reading CSV: {dataset_path}")
    df = pd.read_csv(dataset_path, low_memory=False)
    df.columns = [str(c).strip() for c in df.columns]

    # ── isolate benign rows ──────────────────────────────────────────────
    label_col = next(
        (c for c in df.columns if c.strip().lower() in {"label", "class", "attack_cat"}),
        None,
    )
    if label_col:
        mask = df[label_col].astype(str).str.strip().str.lower().isin({"benign", "normal", "0"})
        benign = df[mask]
        print(f"  Benign rows found: {len(benign):,}  (of {len(df):,} total)")
        if len(benign) < 500:
            print("  Warning: few benign rows, using full dataset for baseline.")
            benign = df
    else:
        benign = df
        print(f"  No label column detected – using all {len(benign):,} rows.")

    df = benign.sample(min(len(benign), 80_000), random_state=42)  # cap for speed

    # ── feature mapping ─────────────────────────────────────────────────
    duration = _first_existing(df, ["Flow Duration", "Duration", "dur", "duration"])
    duration_ms = (duration / 1000.0).clip(1, 3_600_000)

    bytes_sent = _first_existing(
        df, ["Total Length of Fwd Packets", "TotLen Fwd Pkts",
             "bytes_sent", "Src Bytes", "fwd_header_length"]
    ).clip(0)

    bytes_received = _first_existing(
        df, ["Total Length of Bwd Packets", "TotLen Bwd Pkts",
             "bytes_received", "Dst Bytes", "bwd_header_length"]
    ).clip(0)

    fwd_pkts = _first_existing(df, ["Total Fwd Packets", "Tot Fwd Pkts",
                                    "Fwd Packets/s"], 0.0)
    bwd_pkts = _first_existing(df, ["Total Backward Packets", "Tot Bwd Pkts",
                                    "Bwd Packets/s"], 0.0)
    packet_count = (fwd_pkts + bwd_pkts).clip(1, 1_000_000)

    src_port = _first_existing(df, ["Source Port", "Src Port",
                                    "src_port", "sport"], 0.0).clip(0, 65535)
    dst_port = _first_existing(df, ["Destination Port", "Dst Port",
                                    "dst_port", "dport"], 0.0).clip(0, 65535)

    X = np.column_stack([bytes_sent, bytes_received, duration_ms,
                         packet_count, src_port, dst_port]).astype(float)
    mask = np.isfinite(X).all(axis=1)
    X = X[mask]

    if X.shape[0] < 200:
        raise ValueError(
            f"Only {X.shape[0]} valid rows extracted – check CSV column names."
        )
    return X


# ─── main train routine ──────────────────────────────────────────────────────

def train() -> str:
    """Returns 'kaggle' or 'synthetic' indicating training source."""
    dataset_path = os.getenv("KAGGLE_IDS_DATASET", settings.kaggle_ids_dataset).strip()

    if dataset_path and Path(dataset_path).exists():
        print(f"[Trainer] Kaggle dataset detected: {dataset_path}")
        try:
            X = load_kaggle_benign_samples(dataset_path)
            source = "kaggle"
            print(f"[Trainer] Loaded {X.shape[0]:,} samples from Kaggle dataset.")
        except Exception as exc:
            print(f"[Trainer] Kaggle load failed ({exc}). Falling back to synthetic.")
            X = _generate_synthetic_samples()
            source = "synthetic"
    else:
        if dataset_path:
            print(f"[Trainer] KAGGLE_IDS_DATASET path not found: {dataset_path}")
        print("[Trainer] Using synthetic baseline samples.")
        X = _generate_synthetic_samples()
        source = "synthetic"

    print(f"[Trainer] Training IsolationForest on {X.shape[0]:,} samples …")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.02,
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    artifact_dir = Path(settings.model_path).parent
    artifact_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model,          settings.model_path)
    joblib.dump(scaler,         settings.scaler_path)
    joblib.dump(FEATURE_COLUMNS, settings.features_path)

    # persist source tag so dashboard can show "Trained on Kaggle data"
    Path(settings.model_source_path).write_text(source)

    print(f"[Trainer] ✓ Model saved  → {settings.model_path}")
    print(f"[Trainer] ✓ Scaler saved → {settings.scaler_path}")
    print(f"[Trainer] ✓ Source       = {source}")
    return source


if __name__ == "__main__":
    train()
