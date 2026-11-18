import joblib
from feature_extraction import extract_features

# Load trained model
model = joblib.load("model/phishing_model.pkl")

# Check model classes
print("Model classes:", model.classes_)

# Test URLs (synthetic examples)
test_urls = [
    "https://www.google.com",
    "http://paypal-login-verify.example.test/account",
    "http://secure-bank-account-update.example.test/login",
    "https://www.wikipedia.org"
]

for url in test_urls:
    features = extract_features(url)

    prediction = model.predict([list(features.values())])[0]
    probabilities = model.predict_proba(
        [list(features.values())]
    )[0]

    print("\nURL:", url)
    print("Prediction:", prediction)
    print("Probabilities:", probabilities)