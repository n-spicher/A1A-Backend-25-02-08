from flask import Flask, request, jsonify, send_file, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
import PyPDF2
import openai
from dotenv import load_dotenv
from functools import wraps

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()

# Configure CORS properly
CORS(app, 
     origins=["http://localhost:5173"],
     supports_credentials=True,
     allow_headers=["Content-Type"],
     methods=["GET", "POST", "OPTIONS"])

# Configure OpenAI
openai.api_key = os.getenv('OPENAI_API_KEY')

UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        user = User.query.filter_by(username=session['username']).first()
        if user.role != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def load_labels_config():
    try:
        with open('labels_config.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {"labels": [], "labeled_data": []}

def save_labels_config(config):
    with open('labels_config.json', 'w') as f:
        json.dump(config, f, indent=2)

def extract_text_from_pdf(file_path):
    with open(file_path, 'rb') as file:
        pdf_reader = PyPDF2.PdfReader(file)
        text = ''
        page_texts = []
        
        # Process pages in chunks to handle large PDFs
        chunk_size = 100  # Process 100 pages at a time
        total_pages = len(pdf_reader.pages)
        
        for start_idx in range(0, total_pages, chunk_size):
            end_idx = min(start_idx + chunk_size, total_pages)
            chunk_text = ''
            
            # Process this chunk of pages
            for page_num in range(start_idx, end_idx):
                try:
                    page = pdf_reader.pages[page_num]
                    page_text = page.extract_text()
                    chunk_text += f"\n[Page {page_num + 1}]\n{page_text}"
                    page_texts.append({
                        "page": page_num + 1,
                        "text": page_text
                    })
                except Exception as e:
                    print(f"Error processing page {page_num + 1}: {str(e)}")
                    page_texts.append({
                        "page": page_num + 1,
                        "text": f"Error extracting text from page: {str(e)}"
                    })
            
            text += chunk_text
            
        return text, page_texts

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        session['username'] = user.username
        return jsonify({"message": "Login successful", "role": user.role})
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({"message": "Logout successful"})

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and file.filename.endswith('.pdf'):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        # Save the file in chunks
        chunk_size = 8192  # 8KB chunks
        with open(file_path, 'wb') as f:
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
        
        try:
            text, page_texts = extract_text_from_pdf(file_path)
            return jsonify({
                'content': text,
                'filename': filename,
                'pages': page_texts,
                'total_pages': len(page_texts)
            })
        except Exception as e:
            return jsonify({'error': f'Error processing PDF: {str(e)}'}), 500
    
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/get_pdf/<filename>')
@login_required
def get_pdf(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    return send_file(file_path, mimetype='application/pdf')

@app.route('/labels', methods=['GET'])
@login_required
def get_labels():
    config = load_labels_config()
    return jsonify(config)

@app.route('/add_label', methods=['POST'])
@admin_required
def add_label():
    data = request.json
    config = load_labels_config()
    
    new_label = {
        "text": data["text"],
        "label": data["label"],
        "confidence": 1.0,  # Manual labels have 100% confidence
        "source_pdf": data["filename"],
        "page_number": data["page_number"]
    }
    
    config["labeled_data"].append(new_label)
    save_labels_config(config)
    return jsonify({"success": True, "label": new_label})

@app.route('/user_info', methods=['GET'])
@login_required
def user_info():
    username = session.get('username')
    if username:
        user = User.query.filter_by(username=username).first()
        return jsonify({
            "username": username,
            "role": user.role
        })
    return jsonify({"error": "Not logged in"}), 401

@app.route('/admin/users', methods=['POST'])
@admin_required
def manage_users():
    data = request.json
    action = data.get('action')
    username = data.get('username')
    
    if action == 'add':
        if User.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 400
        user = User(username=username, role=data.get('role', 'user'))
        user.set_password(data.get('password'))
        db.session.add(user)
    elif action == 'delete':
        user = User.query.filter_by(username=username).first()
        if user:
            db.session.delete(user)
    elif action == 'edit':
        user = User.query.filter_by(username=username).first()
        if user:
            if 'password' in data:
                user.set_password(data['password'])
            if 'role' in data:
                user.role = data['role']
    
    db.session.commit()
    return jsonify({"message": "User updated successfully"})

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    data = request.json
    query = data.get('query', '')
    filename = data.get('filename', '')
    
    if not filename:
        return jsonify({"error": "No file selected"}), 400
        
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404
    
    try:
        text, page_texts = extract_text_from_pdf(file_path)
        
        # Create a system message that instructs the model to provide page references
        system_message = """You are a helpful assistant analyzing a PDF document. 
        When answering questions:
        1. Always cite the specific page numbers where you found the information
        2. Include relevant quotes from the text to support your answer
        3. If information comes from multiple pages, mention all relevant pages
        4. If you're unsure about something, say so explicitly"""
        
        # Create messages for the chat
        messages = [
            {"role": "system", "content": system_message},
            {"role": "user", "content": f"Here is the PDF content:\n\n{text}\n\nQuestion: {query}"}
        ]
        
        # Get response from OpenAI
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo-16k",  # Using 16k model for longer context
            messages=messages,
            temperature=0.7,
            max_tokens=1000
        )
        
        answer = response.choices[0].message['content']
        
        return jsonify({
            "answer": answer,
            "success": True
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)
