import os
import re
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)
app.secret_key = os.urandom(24)

ph = PasswordHasher()
DB_FILE = 'app.db'

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # Check History Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS check_history (
            check_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            input_type TEXT NOT NULL,
            checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            indicator_summary TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')

    # Learning Content Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS learning_content (
            content_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            red_flags TEXT NOT NULL,
            dos TEXT NOT NULL,
            donts TEXT NOT NULL
        )
    ''')

    # Report Guides Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS report_guides (
            guide_id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            official_url TEXT NOT NULL,
            helpline_number TEXT NOT NULL,
            steps TEXT NOT NULL
        )
    ''')

    cursor.execute('DELETE FROM learning_content')
    cursor.execute('DELETE FROM report_guides')

    modules = [
        (
            "Phishing & Dangerous Links",
            "Phishing Scams",
            "Online criminals pretend to be reputed banks or government offices sending urgent alerts claiming your account has technical issues.",
            "Spelling errors in URLs, odd characters, requests to update KYC via third-party web links.",
            "Verify the sender email/SMS header ID carefully and manually type official portal addresses in the browser.",
            "Never click unverified links or enter your login ID and password on duplicate bank lookalike pages."
        ),
        (
            "OTP, UPI & Payment Frauds",
            "Financial UPI Traps",
            "Scammers send fake money collection requests on UPI apps or pose as bank managers claiming you won cash rewards to drain accounts.",
            "Receiving UPI collect requests for 'receiving' cashback, callers demanding 4 or 6-digit OTP codes.",
            "Remember: Entering your UPI PIN or scanning a QR code is ONLY required to send money, NEVER to receive money.",
            "Never share secret OTP codes, UPI PIN, ATM PIN, or card CVV over phone calls, chat, or email."
        ),
        (
            "Fake Job & Task-Based Scams",
            "Employment Frauds",
            "Bogus work-from-home offers promising high daily payouts for simple tasks like liking videos, followed by demands for advance security fees.",
            "Job offers requiring upfront registration fees, kit fees, or deposits into personal crypto/bank accounts.",
            "Research physical headquarters and cross-check employment listings on official corporate career portals.",
            "Never pay advance deposits or training fees to secure online part-time jobs or freelance projects."
        ),
        (
            "Fake Shopping Websites",
            "E-Commerce Scams",
            "Duplicate shopping stores advertising branded electronics or clothing at 90% discount, delivering worthless items or nothing at all.",
            "Prices that look too good to be true, missing customer service phone numbers, no cash-on-delivery option.",
            "Read third-party seller reviews and confirm physical contact information before placing orders online.",
            "Never make advance payments on unknown websites discovered exclusively via suspicious social media ads."
        ),
        (
            "Social Media & Impersonation Scams",
            "Social Engineering",
            "Hackers take over accounts of friends or relatives and message emergency requests asking for urgent fund transfers.",
            "Unusual payment urgency via gift cards or UPI, refusal to answer voice/video phone calls.",
            "Directly call your friend on their regular mobile phone number to verify any financial distress claim.",
            "Never transfer emergency funds without direct two-way verification."
        )
    ]
    cursor.executemany(
        "INSERT INTO learning_content (title, category, description, red_flags, dos, donts) VALUES (?, ?, ?, ?, ?, ?)",
        modules
    )

    guides = [
        (
            "National Cyber Crime Reporting Helpline",
            "https://cybercrime.gov.in",
            "1930",
            "Dial immediately within the 'Golden Hour' to initiate quick freeze of debited bank amounts."
        ),
        (
            "National Cybercrime Portal",
            "https://cybercrime.gov.in",
            "Official Portal",
            "Register formal e-complaints with evidence (screenshots, bank UTR, suspect contact numbers)."
        ),
        (
            "Bank Immediate Distress Desk",
            "https://www.rbi.org.in",
            "Bank Customer Care",
            "Instantly block debit/credit cards, freeze net-banking access, and register formal transaction dispute."
        )
    ]
    cursor.executemany(
        "INSERT INTO report_guides (title, official_url, helpline_number, steps) VALUES (?, ?, ?, ?)",
        guides
    )

    conn.commit()
    conn.close()

init_db()

def evaluate_scam_heuristics(input_text):
    text_lower = input_text.lower()
    indicators = []
    
    urgency_patterns = [
        r"within \d+ hours?", r"account blocked", r"power disconnection", 
        r"disconnected tonight", r"immediately", r"sim blocked", r"legal action",
        r"suspended tonight", r"update within"
    ]
    for pattern in urgency_patterns:
        if re.search(pattern, text_lower):
            indicators.append("Artificial Panic/Urgency Cue: Threat of immediate account freeze, SIM block, or power disconnection.")
            break

    shorteners = ["bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "wa.me"]
    if any(s in text_lower for s in shorteners):
        indicators.append("Masked / Shortened Web Link: Hidden destination URL attempting to disguise malicious server.")

    if "click on link" in text_lower or "click here" in text_lower or "tap here" in text_lower or "open link" in text_lower or "visit link" in text_lower:
        indicators.append("Suspicious Action Prompt: Direct push forcing user to click unverified external links.")

    if "otp" in text_lower or "upi pin" in text_lower or "enter pin" in text_lower or "atm pin" in text_lower or "cvv" in text_lower:
        indicators.append("Credential Compromise Risk: Direct demand or reference to secret OTP codes, PIN, or CVV.")

    bait_cues = [
        "won lottery", "cash prize", "part-time job", "advance fee", "90% discount",
        "rupees", "rs.", "rs ", "inr", "free recharge", "get 100", "get 500", "earn daily",
        "claim reward", "congratulations", "cashback", "credited"
    ]
    if any(b in text_lower for b in bait_cues):
        indicators.append("Deceptive Financial Bait: Promises of free money, quick cash rewards, or unverified deposits.")

    if "kyc" in text_lower or "verify pan" in text_lower or "aadhaar update" in text_lower:
        indicators.append("Unauthorized KYC Verification Demand: Real banks never ask to update KYC credentials over SMS.")
    risk_level = "High Warning Risk" if len(indicators) >= 2 else ("Moderate Indicator Warning" if len(indicators) == 1 else "No Obvious Indicators Flagged")
    return indicators, risk_level

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/checker', methods=['GET', 'POST'])
def checker():
    results = None
    input_text = ""
    if request.method == 'POST':
        input_text = request.form.get('input_text', '').strip()
        if input_text:
            indicators, risk_level = evaluate_scam_heuristics(input_text)
            results = {
                'indicators': indicators,
                'risk_level': risk_level,
                'input': input_text
            }
            try:
                conn = get_db()
                user_id = session.get('user_id')
                input_type = 'url' if ('http://' in input_text or 'https://' in input_text) else 'text'
                summary = f"{risk_level} - {len(indicators)} cues identified"
                conn.execute(
                    "INSERT INTO check_history (user_id, input_type, indicator_summary) VALUES (?, ?, ?)",
                    (user_id, input_type, summary)
                )
                conn.commit()
                conn.close()
            except Exception:
                pass
        else:
            flash("Please enter a message or URL string to inspect.", "warning")

    return render_template('checker.html', results=results, input_text=input_text)

@app.route('/learn')
def learn():
    conn = get_db()
    modules = conn.execute("SELECT * FROM learning_content").fetchall()
    conn.close()
    return render_template('learn.html', modules=modules)

@app.route('/report-help')
def report_help():
    conn = get_db()
    guides = conn.execute("SELECT * FROM report_guides").fetchall()
    conn.close()
    return render_template('report.html', guides=guides)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not name or not email or not password:
            flash("All registration fields are required.", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Master passwords do not match. Please check again.", "danger")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("Password must be at least 6 characters for Argon2 key derivation.", "warning")
            return redirect(url_for('register'))

        hashed = ph.hash(password)
        try:
            conn = get_db()
            conn.execute("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)", (name, email, hashed))
            conn.commit()
            conn.close()
            flash("Account registered successfully with Argon2 protection! You can now log in.", "success")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("This email address is already registered.", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user:
            try:
                if ph.verify(user['password_hash'], password):
                    session['user_id'] = user['user_id']
                    session['name'] = user['name']
                    flash(f"Welcome back, {user['name']}!", "success")
                    return redirect(url_for('checker'))
            except VerifyMismatchError:
                flash("Invalid login password.", "danger")
        else:
            flash("No user registered with this email.", "danger")
        return redirect(url_for('login'))

    return render_template('login.html')
@app.route('/logout')
def logout():
    session.clear()
    flash("Session terminated.", "info")
    return redirect(url_for('home'))


if __name__ == '__main__':
    app.run(debug=True)
