import os

import joblib
import pandas as pd
import streamlit as st

from feature_extraction import explain, features_to_vector, lookalike_flags

MODEL_PATH = os.path.join("model", "phishing_model.joblib")

st.set_page_config(page_title="PhishGuard", page_icon="🛡️")


@st.cache_resource
def load_model():
    if not os.path.exists(MODEL_PATH):
        return None
    return joblib.load(MODEL_PATH)


bundle = load_model()

st.title("🛡️ PhishGuard")
st.caption("Phishing URL detection using machine learning")

if bundle is None:
    st.error("No trained model found. Run `python train_model.py` first.")
    st.stop()

with st.form("url_form"):
    url = st.text_input("Enter a URL to check", placeholder="https://example.com/login")
    submitted = st.form_submit_button("Check URL", type="primary")

if submitted:
    url = url.strip()
    if not url:
        st.warning("Please enter a URL.")
    else:
        X = pd.DataFrame([features_to_vector(url)], columns=bundle["feature_names"])
        proba = bundle["model"].predict_proba(X)[0]
        classes = list(bundle["model"].classes_)
        p_phish = float(proba[classes.index(1)])

        lookalikes = lookalike_flags(url)

        if p_phish >= 0.5 or lookalikes:
            shown = max(p_phish, 0.9) if lookalikes else p_phish
            st.error(f"⚠️ Likely PHISHING / SUSPICIOUS  ({shown:.1%} risk)")
            st.progress(shown, text=f"Phishing risk: {shown:.1%}")
        else:
            st.success(f"✅ Likely LEGITIMATE  ({1 - p_phish:.1%} confidence)")
            st.progress(p_phish, text=f"Phishing risk: {p_phish:.1%}")

        flags = lookalikes + explain(url)
        st.subheader("Red flags")
        if flags:
            for f in flags:
                st.write(f"- {f}")
        else:
            st.write("No obvious red flags found in the URL.")

st.divider()
st.caption(
    "This tool analyses only the text of the URL. Treat results as one signal, "
    "not a guarantee. Never enter passwords on a site you are unsure about."
)