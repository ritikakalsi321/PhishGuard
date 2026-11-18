"""
PhishGuard - check whether a URL looks legitimate or phishing.

Usage:
    python main.py https://example.com another-url.com
    python main.py                      # interactive mode
"""
import os
import sys

import joblib
import pandas as pd

from feature_extraction import explain, features_to_vector

MODEL_PATH = os.path.join("model", "phishing_model.joblib")


def load_model():
    if not os.path.exists(MODEL_PATH):
        sys.exit("No trained model found. Run:  python train_model.py")
    return joblib.load(MODEL_PATH)


def check(bundle, url):
    X = pd.DataFrame([features_to_vector(url)], columns=bundle["feature_names"])
    proba = bundle["model"].predict_proba(X)[0]
    classes = list(bundle["model"].classes_)
    p_phish = proba[classes.index(1)]
    verdict = "PHISHING" if p_phish >= 0.5 else "LEGITIMATE"

    print(f"\nURL:        {url}")
    print(f"Verdict:    {verdict}  (phishing probability: {p_phish:.1%})")
    flags = explain(url)
    if flags:
        print("Red flags:")
        for f in flags:
            print(f"  - {f}")
    else:
        print("Red flags:  none found")


def main():
    bundle = load_model()
    urls = sys.argv[1:]
    if urls:
        for u in urls:
            check(bundle, u)
        return
    print("PhishGuard - enter a URL (or 'q' to quit)")
    while True:
        u = input("\nURL> ").strip()
        if u.lower() in {"q", "quit", "exit"}:
            break
        if u:
            check(bundle, u)


if __name__ == "__main__":
    main()
