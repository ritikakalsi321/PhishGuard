# 🛡️ PhishGuard – Phishing URL Detection Using Machine Learning

## 📌 About the Project

PhishGuard is a machine learning-based web application designed to identify potentially phishing URLs and distinguish them from legitimate URLs.

Phishing is a type of cyberattack in which attackers create deceptive websites or links to steal sensitive information such as passwords, banking details, and personal data.

PhishGuard analyzes different characteristics of a URL and uses a trained Decision Tree Classifier to predict whether the URL is potentially phishing or legitimate.

The application provides an interactive interface using Streamlit.

## 🎯 Project Objectives

- Detect potentially malicious and phishing URLs.
- Classify URLs as Phishing or Legitimate.
- Apply machine learning techniques to cybersecurity.
- Extract useful features from URLs.
- Provide an easy-to-use interface for URL scanning.
- Display model performance and evaluation results.

## ⚙️ Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main programming language |
| Pandas | Dataset handling and processing |
| NumPy | Numerical operations |
| Scikit-learn | Machine learning model |
| Streamlit | Web application interface |
| Matplotlib | Data visualization |
| Joblib | Saving and loading the trained model |

## 🧠 Machine Learning Algorithm

**Decision Tree Classifier**

PhishGuard uses a Decision Tree Classifier to classify URLs based on extracted URL features.

The model learns patterns from labelled phishing and legitimate URLs during training.

## 🔍 URL Features

The project extracts 17 features from URLs, including:

- URL Length
- Hostname Length
- Path Length
- Number of Dots
- Number of Hyphens
- Number of Special Characters
- Number of Digits
- HTTPS Usage
- IP Address Detection
- Subdomain Count
- Suspicious Word Count

These features are used as input to the machine learning model.

## 🏗️ Project Structure

```text
PhishGuard/
│
├── dataset/
│   └── phishing.csv
│
├── model/
│   ├── phishing_model.pkl
│   ├── performance.json
│   └── confusion_matrix.png
│
├── feature_extraction.py
├── train_model.py
├── main.py
├── app.py
├── diagnose.py
├── test_features.py
├── requirements.txt
├── README.md
└── .gitignore
```

**Note:** The dataset and the additional large model file are excluded from the GitHub repository.

## 🚀 How to Run the Project

### 1. Clone the Repository

```bash
git clone https://github.com/ritikakalsi321/PhishGuard.git
```

### 2. Open the Project Folder

```bash
cd PhishGuard
```

### 3. Create a Virtual Environment

```bash
python -m venv venv
```

### 4. Activate the Virtual Environment

For Windows:

```bash
venv\Scripts\activate
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Run the Application

```bash
streamlit run main.py
```

The application will open in your browser.

## 📊 Model Evaluation

The model is evaluated using the following performance metrics:

- Accuracy
- Precision
- Recall
- F1-Score
- Confusion Matrix

These metrics help evaluate how effectively the model classifies phishing and legitimate URLs.

Actual evaluation results are available in the project's `model/performance.json` file.

## 🔐 Key Features

- URL scanning and classification.
- Machine learning-based phishing detection.
- URL feature extraction.
- Interactive Streamlit dashboard.
- Model performance visualization.
- Prediction confidence display.

## ⚠️ Limitations

- The model primarily analyzes URL-based features.

It may not detect every new or sophisticated phishing attack.

Some legitimate URLs may be incorrectly classified.

Prediction confidence should not be treated as a guarantee of website safety.

PhishGuard is an educational cybersecurity project and should not be considered a replacement for professional security solutions.

👩‍💻 Project Team

Project Name: PhishGuard

Domain: Cyber Security & Machine Learning

Project Type: Academic Major Project

📌 Conclusion

PhishGuard demonstrates how machine learning can be applied to cybersecurity to identify potentially harmful URLs.

The project combines Python, machine learning, and Streamlit to create an interactive phishing URL detection system.