from flask import Flask, render_template, request
import google.generativeai as genai
import os
import PyPDF2
from docx import Document
import pandas as pd
import re
import json
import sqlite3

# Initialize Flask app
app = Flask(__name__)

# Set up the Google API Key
os.environ["GOOGLE_API_KEY"] = "AIzaSyAwL2Rkb-X3Xu8tTD8qV-vUokj2heL2Q1A"
genai.configure(api_key=os.environ["GOOGLE_API_KEY"])

# Initialize the Gemini model
model = genai.GenerativeModel("gemini-2.5-flash")

# ------------------ DATABASE FUNCTIONS ------------------
def init_db():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_type TEXT,
            input_value TEXT,
            result TEXT,
            score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_history(input_type, input_value, result, score=0):
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute("INSERT INTO history (input_type, input_value, result, score) VALUES (?, ?, ?, ?)",
              (input_type, input_value, result, score))
    conn.commit()
    conn.close()

def get_history():
    conn = sqlite3.connect('history.db')
    c = conn.cursor()
    c.execute("SELECT id, input_type, input_value, result, score, created_at FROM history ORDER BY created_at DESC")
    data = c.fetchall()
    conn.close()
    return data
# --------------------------------------------------------

# ------------------ AI FUNCTIONS ------------------------
def predict_fake_or_real_email_content(text):
    prompt = f"""
    You are an expert in identifying scam messages in text, email etc. Analyze the given text and classify it as:

    - **Real/Legitimate** (Authentic, safe message)
    - **Scam/Fake** (Phishing, fraud, or suspicious message)

    **for the following Text:**
    {text}

    **Return a clear message indicating whether this content is real or a scam. 
    If it is a scam, mention why it seems fraudulent. If it is real, state that it is legitimate.**

    **Only return the classification message and nothing else.**
    Note: Don't return empty or null, you only need to return message for the input text
    """

    response = model.generate_content(prompt)
    return response.text.strip() if response else "Classification failed."


def url_detection(url):
    prompt = f"""
    You are an advanced AI model specializing in URL security classification. 
    Analyze the given URL and return:

    1. Threat Class (one of: benign, phishing, malware, defacement)
    2. Threat Level (0 to 100 score, where 0 = completely safe, 100 = extremely dangerous)

    **Output Format (JSON only, no explanation):**
    {{
      "class": "<benign/phishing/malware/defacement>",
      "score": <number>
    }}

    **Input URL:** {url}
    """

    response = model.generate_content(prompt)
    raw_text = response.text if response else ""

    # Extract JSON using regex
    match = re.search(r"\{.*}", raw_text, re.DOTALL)
    if match:
        try:
            data = json.loads(match.group(0))
            return json.dumps(data)  # return clean JSON
        except:
            return '{"class": "unknown", "score": 0}'
    else:
        return '{"class": "unknown", "score": 0}'
# --------------------------------------------------------

# ------------------ ROUTES ------------------------------
@app.route('/')
def home():
    return render_template("index.html")


@app.route('/scam/', methods=['POST'])
def detect_scam():
    if 'file' not in request.files:
        return render_template("index.html", message="No file uploaded.")

    file = request.files['file']
    extracted_text = ""

    # PDF
    if file.filename.endswith('.pdf'):
        pdf_reader = PyPDF2.PdfReader(file)
        extracted_text = " ".join([page.extract_text() for page in pdf_reader.pages if page.extract_text()])

    # TXT
    elif file.filename.endswith('.txt'):
        extracted_text = file.read().decode("utf-8", errors="ignore")

    # DOCX
    elif file.filename.endswith('.docx'):
        doc = Document(file)
        extracted_text = " ".join([para.text for para in doc.paragraphs])

    # CSV
    elif file.filename.endswith('.csv'):
        df = pd.read_csv(file)
        extracted_text = " ".join(df.astype(str).fillna("").values.flatten())

    else:
        return render_template("index.html", message="Invalid file type. Please upload PDF, TXT, DOCX, or CSV.")

    # Empty file check
    if not extracted_text.strip():
        return render_template("index.html", message="File is empty or text could not be extracted.")

    message = predict_fake_or_real_email_content(extracted_text)

    # 🔹 Save to DB
    save_history("file", file.filename, message, 0)

    return render_template("index.html", message=message)


@app.route('/predict', methods=['POST'])
def predict_url():
    url = request.form.get('url', '').strip()

    if not url.startswith(("http://", "https://")):
        return render_template("index.html", message="Invalid URL format.", input_url=url)

    result = url_detection(url)
    try:
        data = json.loads(result)
        classification = data.get("class", "unknown")
        score = int(float(data.get("score", 0)))   # convert to int
    except:
        classification = "unknown"
        score = 0

    # 🔹 Save to DB
    save_history("url", url, classification, score)

    return render_template("index.html", input_url=url, predicted_class=classification, threat_score=score)


@app.route('/history')
def history():
    data = get_history()
    return render_template("history.html", history=data)
# --------------------------------------------------------

# Run App
if __name__ == '__main__':
    init_db()   # DB initialize hoga app start pe
    app.run(debug=True)
