import json
import math
import os
import pathlib
import sys
import warnings

import dill
import numpy as np


DATASET_PATH = pathlib.Path(os.environ.get("VON_DATASET_PATH", r"C:\Users\user\Downloads\vonDataset20180426.dill"))
MODEL_PATH = pathlib.Path(os.environ.get("URL_AI_MODEL_PATH", "models/url-phishing-model.json"))
EPOCHS = int(os.environ.get("VON_AI_EPOCHS", "3"))
BATCH_SIZE = int(os.environ.get("VON_AI_BATCH_SIZE", "8192"))
LEARNING_RATE = float(os.environ.get("VON_AI_LEARNING_RATE", "0.25"))
L2 = float(os.environ.get("VON_AI_L2", "0.00005"))
TARGET_MAX_FPR = float(os.environ.get("VON_AI_TARGET_MAX_FPR", "0.02"))
SEED = int(os.environ.get("VON_AI_SEED", "2026"))


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    warnings.filterwarnings("ignore", category=Warning)
    print(f"Loading dataset: {DATASET_PATH}")
    with DATASET_PATH.open("rb") as handle:
        data = dill.load(handle)

    train_x = np.asarray(data["train_x"], dtype=np.int32)
    train_y = np.asarray(data["train_y"], dtype=np.float32)
    val_x = np.asarray(data["val_x"], dtype=np.int32)
    val_y = np.asarray(data["val_y"], dtype=np.int32)
    test_x = np.asarray(data["test_x"], dtype=np.int32)
    test_y = np.asarray(data["test_y"], dtype=np.int32)
    char_to_int = {str(k): int(v) for k, v in data["char_to_int"].items()}

    max_length = int(train_x.shape[1])
    vocab_size = max(char_to_int.values()) + 1
    print(f"Train={train_x.shape}, Val={val_x.shape}, Test={test_x.shape}, Vocab={vocab_size}")
    print(f"Label counts train: {label_counts(train_y.astype(np.int32))}")

    rng = np.random.default_rng(SEED)
    weights = np.zeros((max_length, vocab_size), dtype=np.float32)
    bias = 0.0

    for epoch in range(EPOCHS):
        order = rng.permutation(train_x.shape[0])
        total_loss = 0.0
        seen = 0
        rate = LEARNING_RATE / (1.0 + epoch * 0.35)
        for start in range(0, order.shape[0], BATCH_SIZE):
            batch_idx = order[start : start + BATCH_SIZE]
            x_batch = train_x[batch_idx]
            y_batch = train_y[batch_idx]

            logits = score(x_batch, weights, bias)
            probs = sigmoid(logits)
            errors = probs - y_batch
            total_loss += logistic_loss(y_batch, probs) * y_batch.shape[0]
            seen += y_batch.shape[0]

            grad_w = np.zeros_like(weights)
            for position in range(max_length):
                np.add.at(grad_w[position], x_batch[:, position], errors)
            weights -= rate * ((grad_w / y_batch.shape[0]) + (L2 * weights))
            bias -= rate * float(np.mean(errors))

        val_probs = sigmoid(score(val_x, weights, bias))
        threshold, val_metrics = choose_threshold(val_y, val_probs, TARGET_MAX_FPR)
        print(
            f"Epoch {epoch + 1}/{EPOCHS} "
            f"loss={total_loss / max(1, seen):.4f} "
            f"val_f1={val_metrics['f1']:.4f} "
            f"val_fpr={val_metrics['false_positive_rate']:.4f} "
            f"threshold={threshold:.4f}"
        )

    val_probs = sigmoid(score(val_x, weights, bias))
    threshold, val_metrics = choose_threshold(val_y, val_probs, TARGET_MAX_FPR)
    test_probs = sigmoid(score(test_x, weights, bias))
    test_metrics = evaluate(test_y, test_probs, threshold)

    model = {
        "modelType": "char_position_logistic",
        "version": 1,
        "trainedAt": utc_now(),
        "source": str(DATASET_PATH),
        "labelMeaning": {"0": "legitimate", "1": "phishing"},
        "maxLength": max_length,
        "padToken": "补",
        "charToInt": char_to_int,
        "weights": np.round(weights, 6).tolist(),
        "bias": round(float(bias), 6),
        "threshold": round(float(threshold), 6),
        "metrics": {
            **{f"validation_{k}": v for k, v in val_metrics.items()},
            **{f"test_{k}": v for k, v in test_metrics.items()},
            "train_count": int(train_y.shape[0]),
            "validation_count": int(val_y.shape[0]),
            "test_count": int(test_y.shape[0]),
            "target_max_false_positive_rate": TARGET_MAX_FPR,
        },
    }

    output_path = pathlib.Path.cwd() / MODEL_PATH if not MODEL_PATH.is_absolute() else MODEL_PATH
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(model, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"Saved model: {output_path}")
    print(json.dumps(model["metrics"], indent=2))


def score(x: np.ndarray, weights: np.ndarray, bias: float) -> np.ndarray:
    rows = np.arange(x.shape[0])
    logits = np.full(x.shape[0], bias, dtype=np.float32)
    for position in range(x.shape[1]):
        logits += weights[position, x[rows, position]]
    return logits


def sigmoid(values: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(values, -35, 35)))


def logistic_loss(y_true: np.ndarray, probs: np.ndarray) -> float:
    clipped = np.clip(probs, 1e-7, 1 - 1e-7)
    return float(np.mean(-(y_true * np.log(clipped) + (1 - y_true) * np.log(1 - clipped))))


def choose_threshold(y_true: np.ndarray, probs: np.ndarray, target_max_fpr: float):
    best = None
    for threshold in np.linspace(0.5, 0.99, 100):
        metrics = evaluate(y_true, probs, float(threshold))
        if metrics["false_positive_rate"] <= target_max_fpr:
            if best is None or metrics["f1"] > best[1]["f1"]:
                best = (float(threshold), metrics)
    if best is not None:
        return best

    fallback = max(
        ((float(t), evaluate(y_true, probs, float(t))) for t in np.linspace(0.5, 0.99, 100)),
        key=lambda item: item[1]["f1"],
    )
    return fallback


def evaluate(y_true: np.ndarray, probs: np.ndarray, threshold: float):
    pred = (probs >= threshold).astype(np.int32)
    y = y_true.astype(np.int32)
    tp = int(np.sum((pred == 1) & (y == 1)))
    fp = int(np.sum((pred == 1) & (y == 0)))
    tn = int(np.sum((pred == 0) & (y == 0)))
    fn = int(np.sum((pred == 0) & (y == 1)))
    accuracy = (tp + tn) / max(1, y.shape[0])
    precision = tp / max(1, tp + fp)
    recall = tp / max(1, tp + fn)
    f1 = (2 * precision * recall) / max(1e-9, precision + recall)
    fpr = fp / max(1, fp + tn)
    return {
        "accuracy": round(float(accuracy), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "false_positive_rate": round(float(fpr), 6),
        "true_positive": tp,
        "false_positive": fp,
        "true_negative": tn,
        "false_negative": fn,
    }


def label_counts(labels: np.ndarray):
    values, counts = np.unique(labels, return_counts=True)
    return {int(value): int(count) for value, count in zip(values, counts)}


def utc_now() -> str:
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
