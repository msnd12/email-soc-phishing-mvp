import json
import os
import pathlib
import sys
import warnings

import dill
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import SGDClassifier


DATASET_PATH = pathlib.Path(os.environ.get("VON_DATASET_PATH", r"C:\Users\user\Downloads\vonDataset20180426.dill"))
MODEL_PATH = pathlib.Path(os.environ.get("URL_AI_MODEL_PATH", "models/url-phishing-model.json"))
EPOCHS = int(os.environ.get("VON_NGRAM_EPOCHS", "4"))
BATCH_SIZE = int(os.environ.get("VON_NGRAM_BATCH_SIZE", "32768"))
N_FEATURES = int(os.environ.get("VON_NGRAM_FEATURES", str(2**20)))
TARGET_MAX_FPR = float(os.environ.get("VON_AI_TARGET_MAX_FPR", "0.02"))
SEED = int(os.environ.get("VON_AI_SEED", "2026"))


def main() -> None:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    warnings.filterwarnings("ignore", category=Warning)
    print(f"Loading dataset: {DATASET_PATH}")
    with DATASET_PATH.open("rb") as handle:
        data = dill.load(handle)

    char_to_int = {str(k): int(v) for k, v in data["char_to_int"].items()}
    int_to_char = {v: k for k, v in char_to_int.items()}
    pad = int_to_char.get(0, "补")

    train_x = np.asarray(data["train_x"], dtype=np.int32)
    train_y = np.asarray(data["train_y"], dtype=np.int32)
    val_x = np.asarray(data["val_x"], dtype=np.int32)
    val_y = np.asarray(data["val_y"], dtype=np.int32)
    test_x = np.asarray(data["test_x"], dtype=np.int32)
    test_y = np.asarray(data["test_y"], dtype=np.int32)

    print(f"Train={train_x.shape}, Val={val_x.shape}, Test={test_x.shape}")
    print(f"Label counts train: {label_counts(train_y)}")

    vectorizer = HashingVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        n_features=N_FEATURES,
        alternate_sign=False,
        lowercase=True,
        norm="l2",
    )
    classifier = SGDClassifier(
        loss="log_loss",
        alpha=1e-6,
        penalty="l2",
        random_state=SEED,
        learning_rate="optimal",
        average=True,
    )

    rng = np.random.default_rng(SEED)
    classes = np.array([0, 1], dtype=np.int32)
    for epoch in range(EPOCHS):
        order = rng.permutation(train_x.shape[0])
        for batch_number, start in enumerate(range(0, order.shape[0], BATCH_SIZE), start=1):
            idx = order[start : start + BATCH_SIZE]
            urls = decode_many(train_x[idx], int_to_char, pad)
            matrix = vectorizer.transform(urls)
            classifier.partial_fit(matrix, train_y[idx], classes=classes)
            if batch_number % 10 == 0:
                print(f"Epoch {epoch + 1}/{EPOCHS} batch {batch_number}")

        val_probs = predict_probabilities(classifier, vectorizer, val_x, int_to_char, pad)
        threshold, metrics = choose_threshold(val_y, val_probs, TARGET_MAX_FPR)
        print(
            f"Epoch {epoch + 1}/{EPOCHS} "
            f"val_f1={metrics['f1']:.4f} "
            f"val_precision={metrics['precision']:.4f} "
            f"val_recall={metrics['recall']:.4f} "
            f"val_fpr={metrics['false_positive_rate']:.4f} "
            f"threshold={threshold:.4f}"
        )

    val_probs = predict_probabilities(classifier, vectorizer, val_x, int_to_char, pad)
    threshold, val_metrics = choose_threshold(val_y, val_probs, TARGET_MAX_FPR)
    test_probs = predict_probabilities(classifier, vectorizer, test_x, int_to_char, pad)
    test_metrics = evaluate(test_y, test_probs, threshold)

    weights = classifier.coef_[0].astype(np.float32)
    model = {
        "modelType": "hashed_ngram_logistic",
        "version": 1,
        "trainedAt": utc_now(),
        "source": str(DATASET_PATH),
        "labelMeaning": {"0": "legitimate", "1": "phishing"},
        "nFeatures": N_FEATURES,
        "ngramMin": 3,
        "ngramMax": 5,
        "lowercase": True,
        "norm": "l2",
        "weights": np.round(weights, 6).tolist(),
        "bias": round(float(classifier.intercept_[0]), 6),
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
    output_path.write_text(json.dumps(model, indent=2), encoding="utf-8")
    print(f"Saved model: {output_path}")
    print(json.dumps(model["metrics"], indent=2))


def decode_many(rows: np.ndarray, int_to_char: dict[int, str], pad: str) -> list[str]:
    result = []
    for row in rows:
        value = "".join(int_to_char.get(int(item), "") for item in row)
        result.append(value.replace(pad, ""))
    return result


def predict_probabilities(classifier: SGDClassifier, vectorizer: HashingVectorizer, x: np.ndarray, int_to_char, pad) -> np.ndarray:
    chunks = []
    for start in range(0, x.shape[0], BATCH_SIZE):
        urls = decode_many(x[start : start + BATCH_SIZE], int_to_char, pad)
        matrix = vectorizer.transform(urls)
        chunks.append(classifier.predict_proba(matrix)[:, 1])
    return np.concatenate(chunks)


def choose_threshold(y_true: np.ndarray, probs: np.ndarray, target_max_fpr: float):
    best = None
    for threshold in np.linspace(0.05, 0.99, 150):
        metrics = evaluate(y_true, probs, float(threshold))
        if metrics["false_positive_rate"] <= target_max_fpr:
            if best is None or metrics["f1"] > best[1]["f1"]:
                best = (float(threshold), metrics)
    if best is not None:
        return best
    return max(
        ((float(t), evaluate(y_true, probs, float(t))) for t in np.linspace(0.05, 0.99, 150)),
        key=lambda item: item[1]["f1"],
    )


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
