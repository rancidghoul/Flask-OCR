from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from PIL import Image
import pytesseract
import os
import gridfs
from pymongo import MongoClient
import io
import bcrypt  # For password hashing
import google.generativeai as genai
from bson import ObjectId


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# Set up Tesseract
pytesseract.pytesseract.tesseract_cmd = "C:\\Program Files\\Tesseract-OCR\\tesseract.exe"

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['image_database']
fs = gridfs.GridFS(db)

# MongoDB for user profiles
user_db = client['user_profiles']  # New database for user profiles
users_collection = user_db['users']  # Collection for storing user info

# MongoDB for uploaded images metadata
# uploads_db = client['uploads_database']  # New database for uploaded images
# # uploads_collection = uploads_db['uploads']  # Collection for storing uploads metadata
# fs = gridfs.GridFS(uploads_db)

genai.configure(api_key="AIzaSyCEtlyVqsp7w2LOwAi0lNC2m_Fllr1FVgw")
generation_config = {
    "temperature": 1,
    "top_p": 0.95,
    "top_k": 40,
    "max_output_tokens": 8192,
    "response_mime_type": "text/plain",
}

model = genai.GenerativeModel(
    model_name="gemini-1.5-flash-8b",
    generation_config=generation_config,
)

def process_text(input_string):
    output_string = []
    space_flag = False
    for index in range(len(input_string)):
        if input_string[index] != ' ':
            if space_flag:
                if input_string[index] not in ['.', '?', ',']:
                    output_string.append(' ')
                space_flag = False
            output_string.append(input_string[index])
        elif input_string[index - 1] != ' ':
            space_flag = True
    return ''.join(output_string)

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']

        # Check if the user already exists
        existing_user = users_collection.find_one({'email': email})
        if existing_user:
            return "User with that email already exists. Please log in."

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Store the new user in the database
        users_collection.insert_one({
            'username': username,
            'email': email,
            'phone': phone,
            'password': hashed_password
        })

        return redirect(url_for('login'))
    return render_template('register.html')

# Login Route
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Find the user in the database
        user = users_collection.find_one({'email': email})
        if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
            session['logged_in'] = True
            session['username'] = user['username']
            return redirect(url_for('index'))
        else:
            return "Invalid credentials. Please try again."

    return render_template('login.html')

# Upload Route (only accessible when logged in)
@app.route('/index')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    try:
        file = request.files['file']
        file_id = fs.put(file, filename=file.filename, content_type=file.content_type)
        user_input = request.form.get('user_input')
        # Read the uploaded image
        stored_file = fs.get(file_id)
        img = Image.open(io.BytesIO(stored_file.read()))
        text = pytesseract.image_to_string(img)
        processed_text = process_text(text)

        # Generate instructions and caption
        chat_session = model.start_chat(
            history=[{"role": "user", "parts": [processed_text]}]
        )
    
        detailed_instructions = chat_session.send_message(processed_text + " Give detailed testing instructions for each component"+user_input )
        caption = chat_session.send_message(processed_text + " Give a one-line caption for the above information")

        # Store the metadata in uploads collection
        db.fs.files.update_one(
            {'_id': file_id},
            {'$set': {
                'user_name': session['username'],
                'filename': file.filename,
                'file_id':file_id,
                'content_type':file.content_type,
                'caption': caption.text  # Only store the caption
            }}
        )

        return jsonify({
            'caption': caption.text,
            'detailed_instructions': detailed_instructions.text,
            'file_id': str(file_id)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Profile Route
@app.route('/profile')
def profile():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    user_email = users_collection.find_one({'username': session['username']})['email']
    user_phone = users_collection.find_one({'username': session['username']})['phone']
    upload_count = db.fs.files.count_documents({'user_name': session['username']})
    return render_template('profile.html', username=session['username'], email=user_email, phone=user_phone, upload_count=upload_count)

@app.route('/user_uploads')
def user_uploads():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    uploads = list(db.fs.files.find({'user_name':session['username']}))  # Fetch all files stored in GridFS
    # uploads = uploads_db.fs.files.find({'user_name':session['username']}) 
    return render_template('user_uploads.html', uploads=uploads)

@app.route('/get_file/<file_id>')
def get_file(file_id):
    """Serve the uploaded file from MongoDB using its file_id."""
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    try:
        # Fetch the file from GridFS using its file_id
        file = fs.get(ObjectId(file_id))
        return file.read(), 200, {'Content-Type': file.content_type}
    except Exception as e:
        return jsonify({'error': str(e)}), 404  # Handle file not found errors

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
