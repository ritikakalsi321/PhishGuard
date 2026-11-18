from feature_extraction import extract_features

url = "http://example-login-verify.com"

result = extract_features(url)

print("Input URL:", url)
print("\nExtracted Features:")

for feature, value in result.items():
    print(feature, ":", value)