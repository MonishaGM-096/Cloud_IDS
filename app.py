from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import joblib
import numpy as np
import pandas as pd
import os
import requests
from bs4 import BeautifulSoup
from readability.readability import Document
import re  
from flask_bcrypt import Bcrypt
import MySQLdb
import config
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # You should use a more secure key in production
bcrypt = Bcrypt(app)

def get_db():
    return MySQLdb.connect(
        host=config.db_host,
        user=config.db_user,
        passwd=config.db_password,
        db=config.db_name
    )

# Load model, scaler, and selected features
model = joblib.load("random_forest_nsl_kdd.pkl")
scaler = joblib.load("scaler.pkl")
selected_features = joblib.load("selected_features.pkl")

# Define column names for displaying reasoning
feature_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", 
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", 
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", 
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds", 
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate", 
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", 
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", 
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", 
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", 
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", 
    "dst_host_srv_rerror_rate"
]

# Dictionary of common attack types and their characteristics
attack_patterns = {
    "DoS": {
        "description": "Denial of Service attack attempts to make a machine or network resource unavailable",
        "indicators": ["high count", "high serror_rate", "high src_bytes", "low dst_bytes"]
    },
    "Probe": {
        "description": "Surveillance and probing for vulnerabilities",
        "indicators": ["multiple services", "high dst_host_count", "low duration"]
    },
    "R2L": {
        "description": "Remote to Local attack - unauthorized access from a remote machine",
        "indicators": ["high hot", "num_failed_logins", "root_shell", "high dst_bytes"]
    },
    "U2R": {
        "description": "User to Root attack - unauthorized access to local superuser privileges",
        "indicators": ["high num_file_creations", "num_shells", "num_root", "su_attempted"]
    }
}

# Feature importance thresholds
IMPORTANT_THRESHOLD = 0.75  # Only show features above this percentile for importance

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

trusted_domains = [
    'amazon.com', 'google.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'microsoft.com', 'apple.com', 'youtube.com', 'github.com', 'wikipedia.org',
    'instagram.com', 'netflix.com', 'reddit.com', 'paypal.com', 'dropbox.com',
    'whatsapp.com', 'zoom.us', 'adobe.com', 'bbc.com', 'cnn.com',
    'stackexchange.com', 'stackoverflow.com', 'quora.com', 'cloudflare.com',
    'aitchnu.com'
]

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to access this page", "warning")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", 
                           (name, email, hashed_pw))
            conn.commit()
            flash("Signup successful! Please login.", "success")
            return redirect(url_for('login'))
        except MySQLdb.IntegrityError:
            flash("Email already exists!", "danger")
        finally:
            cursor.close()
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user and bcrypt.check_password_hash(user[3], password):
            session['user_id'] = user[0]
            session['name'] = user[1]
            flash("Login successful!", "success")
            next_page = request.args.get('next')
            return redirect(next_page if next_page else url_for('index'))
        else:
            flash("Invalid credentials", "danger")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for('index'))

@app.route('/')
def index():
    return render_template("index.html")

def is_trusted_domain(url):
    try:
        domain = url.split('/')[2]
        return any(trusted_domain in domain for trusted_domain in trusted_domains)
    except IndexError:
        return False

def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['num_dots'] = url.count('.')
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_at'] = url.count('@')
    features['num_question'] = url.count('?')
    features['num_equal'] = url.count('=')
    features['num_digits'] = len(re.findall(r'\d', url))
    features['has_ip'] = int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', url)))
    features['num_subdomains'] = len(url.split('.')) - 2
    features['https'] = int('https' in url.lower())
    features['has_suspicious_words'] = int(any(word in url.lower() for word in ['login', 'secure', 'account', 'update', 'verify']))
    return pd.DataFrame([features])

def generate_reason(data_row, prediction):
    """Generate a human-readable reason for the prediction based on key features"""
    # Get feature importances from the model
    importances = model.feature_importances_
    
    # Get the original features from selected_features
    selected_feature_names = [feature_names[i] for i in selected_features]
    
    # Zip feature names, values and importances
    features_data = list(zip(selected_feature_names, data_row, importances))
    
    # Sort by importance
    features_data.sort(key=lambda x: x[2], reverse=True)
    
    # Get top features (above threshold)
    top_percentile = np.percentile([imp for _, _, imp in features_data], 100 - IMPORTANT_THRESHOLD * 100)
    top_features = [(name, value) for name, value, imp in features_data if imp >= top_percentile]
    
    # Generate reason
    if prediction == 1:  # Attack
        # Identify potential attack type
        attack_type = "Unknown"
        attack_confidence = 0
        attack_reasons = []
        
        for attack, info in attack_patterns.items():
            match_count = 0
            relevant_indicators = []
            
            for indicator in info["indicators"]:
                words = indicator.split()
                feature_name = words[-1].strip()
                magnitude = words[0] if len(words) > 1 else ""
                
                for name, value in top_features:
                    if feature_name in name:
                        is_high = (magnitude == "high" and value > 0.5) or (magnitude != "high" and magnitude != "low")
                        is_low = (magnitude == "low" and value <= 0.5) or (magnitude != "high" and magnitude != "low")
                        
                        if (is_high or is_low):
                            match_count += 1
                            relevant_indicators.append(f"{name} = {value:.4f}")
            
            confidence = match_count / len(info["indicators"]) if info["indicators"] else 0
            if confidence > attack_confidence:
                attack_confidence = confidence
                attack_type = attack
                attack_reasons = relevant_indicators
        
        # Format reasons
        reason = f"Potential {attack_type} Attack Detected ({attack_confidence*100:.0f}% confidence)\n"
        reason += f"Description: {attack_patterns[attack_type]['description']}\n"
        reason += "Key indicators:\n"
        for i, indicator in enumerate(attack_reasons[:3]):  # Limit to top 3
            reason += f"- {indicator}\n"
        
        # Add general info about other significant features
        if len(top_features) > len(attack_reasons):
            reason += "\nOther significant features:\n"
            for name, value in top_features[:3]:  # Limit to top 3
                if not any(name in r for r in attack_reasons):
                    reason += f"- {name} = {value:.4f}\n"
    
    else:  # Normal traffic
        reason = "Normal Network Traffic\n"
        reason += "This traffic pattern displays typical characteristics:\n"
        
        # List key normal indicators
        normal_indicators = []
        for name, value in top_features[:5]:  # Top 5 features
            if "error" in name.lower() and value < 0.1:
                normal_indicators.append(f"Low error rate: {name} = {value:.4f}")
            elif "count" in name.lower() and value < 0.5:
                normal_indicators.append(f"Normal connection count: {name} = {value:.4f}")
            elif "bytes" in name.lower():
                normal_indicators.append(f"Normal data transfer: {name} = {value:.4f}")
            else:
                normal_indicators.append(f"{name} = {value:.4f}")
        
        for i, indicator in enumerate(normal_indicators[:5]):  # Limit to top 5
            reason += f"- {indicator}\n"
    
    return reason

@app.route("/predict", methods=["POST"])
@login_required
def predict():
    try:
        if "file" not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files["file"]
        if file.filename == "":
            return jsonify({"error": "No selected file"}), 400

        file_path = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(file_path)

        if file.filename.endswith(".csv"):
            df = pd.read_csv(file_path)
        else:
            df = pd.read_csv(file_path, delimiter="\\s+", header=None)

        if df.shape[1] != 41:
            return jsonify({"error": "Invalid number of features"}), 400

        features_scaled = scaler.transform(df)
        features_selected = features_scaled[:, selected_features]

        predictions = model.predict(features_selected)
        
        # Generate reasoning for each prediction
        results = []
        for i, pred in enumerate(predictions):
            pred_result = "Attack Detected" if pred == 1 else "Normal Traffic"
            reason = generate_reason(features_selected[i], pred)
            results.append({
                "prediction": pred_result,
                "reason": reason
            })

        # Save prediction to database
        conn = get_db()
        cursor = conn.cursor()
        try:
            # Count attacks and normal traffic
            attack_count = sum(1 for r in results if r["prediction"] == "Attack Detected")
            normal_count = len(results) - attack_count
            
            # Insert prediction summary
            cursor.execute(
                "INSERT INTO predictions (user_id, filename, total_records, attack_count, normal_count) VALUES (%s, %s, %s, %s, %s)",
                (session['user_id'], file.filename, len(results), attack_count, normal_count)
            )
            conn.commit()
        except Exception as e:
            # Log database error but don't interrupt the response
            print(f"Database error: {str(e)}")
        finally:
            cursor.close()
            conn.close()

        return jsonify({"predictions": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/scrape', methods=['GET', 'POST'])
@login_required
def scrape():
    if request.method == 'POST':
        page_url = request.form.get("page_url")
        if not page_url:
            return render_template("scrape.html", error="Please enter a URL")

        try:
            response = requests.get(page_url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')
            links = [a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http')]

            results = []
            for link in links:
                if is_trusted_domain(link):
                    label = "benign"
                else:
                    features = extract_features(link)
                    label = "unknown"
                results.append({'url': link, 'result': label})

            return render_template("scrape.html", results=results, page_url=page_url)

        except Exception as e:
            return render_template("scrape.html", error=f"Error: {str(e)}")

    return render_template("scrape.html")

@app.route('/extract_content', methods=['GET', 'POST'])
@login_required
def extract_content():
    if request.method == 'POST':
        page_url = request.form.get("page_url")
        if not page_url:
            return render_template("content.html", error="Please enter a valid URL.")

        try:
            response = requests.get(page_url, timeout=10)
            doc = Document(response.text)
            title = doc.short_title()
            html = doc.summary()

            soup = BeautifulSoup(html, 'html.parser')
            content = soup.get_text(separator="\n")

            return render_template("content.html", page_url=page_url, title=title, content=content)

        except Exception as e:
            return render_template("content.html", error=f"Error: {str(e)}")

    return render_template("content.html")

@app.route('/predict123')
@login_required
def predict123():
    return render_template("predict.html")

@app.route('/view_prediction/<int:prediction_id>')
@login_required
def view_prediction(prediction_id):
    conn = get_db()
    cursor = conn.cursor(MySQLdb.cursors.DictCursor)  # Use DictCursor for named columns
    
    try:
        # First verify that this prediction belongs to the current user
        cursor.execute(
            "SELECT id, filename, total_records, attack_count, normal_count, created_at "
            "FROM predictions WHERE id = %s AND user_id = %s",
            (prediction_id, session['user_id'])
        )
        prediction = cursor.fetchone()
        
        if not prediction:
            flash("Prediction not found or you don't have permission to view it", "danger")
            return redirect(url_for('history'))
        
        # Convert to tuple if needed for backward compatibility
        prediction_tuple = (
            prediction['id'],
            prediction['filename'],
            prediction['total_records'],
            prediction['attack_count'],
            prediction['normal_count'],
            prediction['created_at']
        )
        
        return render_template(
            "view_prediction.html",
            prediction=prediction_tuple
        )
        
    except Exception as e:
        flash(f"Error retrieving prediction: {str(e)}", "danger")
        return redirect(url_for('history'))
        
    finally:
        cursor.close()
        conn.close()


@app.route('/history')
@login_required
def history():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, filename, total_records, attack_count, normal_count, created_at FROM predictions WHERE user_id = %s ORDER BY created_at ASC",
        (session['user_id'],)
    )
    predictions = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template("history.html", predictions=predictions)

if __name__ == "__main__":
    app.run(debug=True)