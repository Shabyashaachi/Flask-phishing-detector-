from flask import Flask, render_template, jsonify
from flask_sqlalchemy import SQLAlchemy
import imaplib, email, re, smtplib, requests, os
from email.header import decode_header
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///emails.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy()
db.init_app(app)


# Database Model for Storing Emails
class EmailLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(200))
    subject = db.Column(db.String(500))
    urls = db.Column(db.Text)
    phishing_detected = db.Column(db.Boolean, default=False)


# Function to Connect to Email Server
def connect_email():
    try:
        mail = imaplib.IMAP4_SSL(os.getenv("EMAIL_IMAP_SERVER"))
        mail.login(os.getenv("EMAIL_ADDRESS"), os.getenv("EMAIL_PASSWORD"))
        mail.select("inbox")
        return mail
    except imaplib.IMAP4.error as e:
        print(f"❌ IMAP Error: {e}")
    except Exception as e:
        print(f"❌ Error Connecting to Email: {e}")
    return None


# Function to Extract URLs from Email Body
def extract_urls(email_text):
    return re.findall(r'https?://[\w.-]+', email_text)


# Function to Check URL Reputation
def check_url_reputation(url):
    try:
        api_key = os.getenv("PHISHTANK_API_KEY")
        if not api_key:
            return "API Key Missing"
        response = requests.post("https://checkurl.phishtank.com/checkurl/",
                                 data={"format": "json", "app_key": api_key, "url": url},
                                 timeout=5)
        return "Phishing Detected" if "phishing" in response.text.lower() else "Safe"
    except requests.RequestException:
        return "Error Checking URL"


# Function to Scan Inbox for Phishing Emails
def scan_inbox():
    mail = connect_email()
    if not mail:
        return []

    _, messages = mail.search(None, 'UNSEEN')
    email_ids = messages[0].split()
    results = []

    for email_id in email_ids:
        _, msg_data = mail.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg.get("Subject"))[0]
                subject = subject.decode(encoding) if isinstance(subject, bytes) and encoding else subject
                sender = msg.get("From")
                email_body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            email_body = part.get_payload(decode=True).decode(errors='ignore')
                            break
                else:
                    email_body = msg.get_payload(decode=True).decode(errors='ignore')

                urls = extract_urls(email_body)
                phishing_detected = any(check_url_reputation(url) == "Phishing Detected" for url in urls)
                new_email = EmailLog(sender=sender, subject=subject, urls=", ".join(urls),
                                     phishing_detected=phishing_detected)
                db.session.add(new_email)
                db.session.commit()

                if phishing_detected:
                    send_alert_email(sender, subject, urls)

                results.append({"sender": sender, "subject": subject, "urls": urls, "phishing": phishing_detected})

    mail.logout()
    return results


# Function to Send Alert Email
def send_alert_email(sender, subject, urls):
    try:
        server = smtplib.SMTP(os.getenv("EMAIL_SMTP_SERVER"), 587)
        server.starttls()
        server.login(os.getenv("EMAIL_ADDRESS"), os.getenv("EMAIL_PASSWORD"))
        message = f"Subject: ⚠️ Phishing Alert!\n\nSuspicious email detected.\nSender: {sender}\nSubject: {subject}\nURLs: {', '.join(urls)}"
        server.sendmail(os.getenv("EMAIL_ADDRESS"), os.getenv("ALERT_RECIPIENT"), message)
        server.quit()
    except smtplib.SMTPException as e:
        print(f"❌ Failed to send alert email: {e}")


# Flask Routes
@app.route('/')
def index():
    try:
        emails = EmailLog.query.all()
        return render_template('index.html', emails=emails)
    except Exception as e:
        import traceback
        print("❌ Error loading page:", traceback.format_exc())
        return jsonify({"error": str(e)}), 500


@app.route('/scan')
def scan():
    results = scan_inbox()
    return jsonify(results)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

# README.md (Guidance for Setup and Deployment)
README_CONTENT = """
# Phishing Email Detector 🚀

This project is a **phishing email detection system** that:
✅ Connects to an email inbox
✅ Scans emails for phishing links
✅ Sends alerts if a phishing attempt is detected

## 🔧 Setup Instructions

1. **Clone the Repository:**
```sh
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector
```

2. **Install Dependencies:**
```sh
pip install -r requirements.txt
```

3. **Set Up Environment Variables:**
Create a `.env` file and configure:
```
EMAIL_IMAP_SERVER=imap.yourmail.com
EMAIL_SMTP_SERVER=smtp.yourmail.com
EMAIL_ADDRESS=your_email@example.com
EMAIL_PASSWORD=your_password
ALERT_RECIPIENT=alert_recipient@example.com
PHISHTANK_API_KEY=your_api_key
```

4. **Run the Application:**
```sh
python phishing_detector.py
```

## 📤 Deploy to GitHub
```sh
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/yourusername/phishing-detector.git
git push -u origin main
```

## 🚀 Next Steps
- ✅ Deploy as a web service
- ✅ Improve phishing detection with ML
- ✅ Automate email reporting

"""

# Save README to the project directory
with open("README.md", "w") as readme_file:
    readme_file.write(README_CONTENT)
