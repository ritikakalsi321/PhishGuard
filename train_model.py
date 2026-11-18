"""
Train the PhishGuard classifier.

Usage:
    python train_model.py
    python train_model.py --data dataset/phishing.csv --out model/phishing_model.joblib

The CSV needs a URL column (url / URL) and a label column (label / Label /
status / class / type). Phishing values: 1, phishing, bad, malicious.
Legitimate values: 0, legitimate, good, benign, safe.
"""
import argparse
import os

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

from feature_extraction import FEATURE_NAMES, features_to_vector

URL_COLUMNS = ["url", "urls", "link"]
LABEL_COLUMNS = ["label", "status", "class", "type", "result"]
PHISHING = {"1", "phishing", "bad", "malicious", "yes"}
LEGIT = {"0", "legitimate", "good", "benign", "safe", "no"}


def find_column(df, candidates):
    lowered = {c.lower().strip(): c for c in df.columns}
    for name in candidates:
        if name in lowered:
            return lowered[name]
    raise SystemExit(f"Could not find any of {candidates} in columns: {list(df.columns)}")


def load_dataset(path):
    df = pd.read_csv(path)
    url_col = find_column(df, URL_COLUMNS)
    label_col = find_column(df, LABEL_COLUMNS)

    def to_label(v):
        s = str(v).strip().lower()
        if s in PHISHING:
            return 1
        if s in LEGIT:
            return 0
        return None

    df = df[[url_col, label_col]].rename(columns={url_col: "url", label_col: "label"})
    df["label"] = df["label"].map(to_label)
    dropped = df["label"].isna().sum()
    if dropped:
        print(f"Warning: dropped {dropped} rows with unrecognised labels")
    df = df.dropna().drop_duplicates(subset="url")
    df["label"] = df["label"].astype(int)
    return df


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="dataset/phishing.csv")
    parser.add_argument("--out", default="model/phishing_model.joblib")
    args = parser.parse_args()

    df = load_dataset(args.data)
    print(f"Loaded {len(df)} URLs  (phishing={int(df.label.sum())}, legitimate={int((df.label == 0).sum())})")

    X = pd.DataFrame([features_to_vector(u) for u in df["url"]], columns=FEATURE_NAMES)
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    model = RandomForestClassifier(
    n_estimators=100,   
    max_depth=25,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1,
    verbose=1,
    )
    print("Training model... (this can take a few minutes)")
    model.fit(X_train, y_train)

    pred = model.predict(X_test)
    print("\nConfusion matrix [rows=true, cols=pred] (0=legit, 1=phishing):")
    print(confusion_matrix(y_test, pred))
    print("\n" + classification_report(y_test, pred, target_names=["legitimate", "phishing"]))

    print("Top features:")
    ranked = sorted(zip(FEATURE_NAMES, model.feature_importances_), key=lambda t: -t[1])
    for name, score in ranked[:10]:
        print(f"  {name:<24}{score:.3f}")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump({"model": model, "feature_names": FEATURE_NAMES}, args.out)
    print(f"\nModel saved to {args.out}")


if __name__ == "__main__":
    main()
