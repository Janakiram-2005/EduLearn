import os
from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId
import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from functools import wraps

# --- 1. CONFIGURATION & SETUP ---
load_dotenv()
app = Flask(__name__, static_folder='static')
# In app.py

# List of all frontend URLs that are allowed to talk to this backend
allowed_origins = [
    "https://edulearn-tekj.onrender.com",  # Your deployed frontend
    "http://127.0.0.1:5001"               # Your local development server (from the error)
]

# This is the line to update
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

# --- 2. DATABASE & SECURITY CONFIG ---
MONGO_URI = os.getenv("MONGO_URI")
JWT_SECRET = os.getenv("JWT_SECRET", "default-super-secret-key")
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "your-admin-secret-for-registration")

if not MONGO_URI:
    raise Exception("FATAL ERROR: MONGO_URI not found in .env file!")

# --- 3. DATABASE CONNECTION ---
try:
    client = MongoClient(MONGO_URI) 
    db = client.get_database("school_db")
    users_collection = db.users
    teachers_collection = db.teachers
    students_collection = db.students
    feedback_collection = db.feedback
    admins_collection = db.admins
    notifications_collection = db.notifications # Added for completeness
    client.admin.command('ping')
    print("✅ MongoDB connection successful.")
except Exception as e:
    print(f"❌ Could not connect to MongoDB. Error: {e}")
    exit()

# --- 4. HELPER FUNCTIONS & DECORATORS ---
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(stored_hashed_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_hashed_password)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').split(" ")[-1]
        if not token: return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user: return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!', 'error': str(e)}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def admin_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').split(" ")[-1]
        if not token: return jsonify({'message': 'Admin token is missing!'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            if not data.get('is_admin'): return jsonify({'message': 'Admin privileges required!'}), 403
            current_admin = admins_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_admin: return jsonify({'message': 'Admin user not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!', 'error': str(e)}), 401
        return f(current_admin, *args, **kwargs)
    return decorated

def no_cache(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        response = make_response(f(*args, **kwargs))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response
    return decorated_function

# --- 5. AUTHENTICATION ROUTES ---
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    username, email, password, school_name = data.get("username"), data.get("email"), data.get("password"), data.get("school_name")
    if not all([username, email, password, school_name]):
        return jsonify({"message": "All fields are required"}), 400
    if users_collection.find_one({"$or": [{"email": email}, {"username": username}]}):
        return jsonify({"message": "A user with that email or username already exists"}), 409
    users_collection.insert_one({
        "school_name": school_name, "username": username, "email": email, 
        "password": hash_password(password), "contact": "", "location": "", "grades": "", "affiliation": ""
    })
    return jsonify({"message": "School account registered successfully"}), 201

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    username, password = data.get("username"), data.get("password")
    user = users_collection.find_one({"username": username})
    if not user or not check_password(user["password"], password):
        return jsonify({"message": "Invalid username or password"}), 401
    payload = { "user_id": str(user["_id"]), "exp": datetime.now(timezone.utc) + timedelta(hours=24) }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"message": "Login successful", "token": token}), 200

@app.route("/api/admin/register", methods=["POST"])
def admin_register():
    data = request.get_json()
    username, password, secret_key = data.get("username"), data.get("password"), data.get("secret_key")
    if secret_key != ADMIN_SECRET_KEY: return jsonify({"message": "Invalid secret key for admin registration"}), 403
    if admins_collection.find_one({"username": username}): return jsonify({"message": "Admin user already exists"}), 409
    admins_collection.insert_one({ "username": username, "password": hash_password(password) })
    return jsonify({"message": "Admin account registered successfully"}), 201

@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.get_json()
    username, password = data.get("username"), data.get("password")
    admin = admins_collection.find_one({"username": username})
    if not admin or not check_password(admin["password"], password):
        return jsonify({"message": "Invalid admin username or password"}), 401
    payload = { "user_id": str(admin["_id"]), "is_admin": True, "exp": datetime.now(timezone.utc) + timedelta(hours=8) }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return jsonify({"message": "Admin login successful", "token": token}), 200

# --- 8. ADMIN-ONLY ROUTES ---

# ... (keep all your existing admin routes like get_dashboard_data, get_all_feedback, etc.) ...

# NEW ROUTE: Get all students from all schools for the admin
@app.route("/api/admin/students", methods=["GET"])
@admin_token_required
def get_all_students(current_admin):
    try:
        # Use an aggregation pipeline to join students with their school's name
        pipeline = [
            {
                '$lookup': {
                    'from': 'users', # This is your schools collection
                    'localField': 'school_id',
                    'foreignField': '_id',
                    'as': 'school'
                }
            },
            { '$unwind': '$school' },
            {
                '$project': {
                    '_id': 1,
                    'name': 1,
                    'grade': 1,
                    'school_name': '$school.school_name'
                }
            }
        ]
        all_students = list(students_collection.aggregate(pipeline))
        for s in all_students:
            s['_id'] = str(s['_id'])
        return jsonify(all_students)
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

# NEW ROUTE: Get all teachers from all schools for the admin
@app.route("/api/admin/teachers", methods=["GET"])
@admin_token_required
def get_all_teachers(current_admin):
    try:
        pipeline = [
            {
                '$lookup': {
                    'from': 'users', # This is your schools collection
                    'localField': 'school_id',
                    'foreignField': '_id',
                    'as': 'school'
                }
            },
            { '$unwind': '$school' },
            {
                '$project': {
                    '_id': 1,
                    'name': 1,
                    'subject': 1,
                    'school_name': '$school.school_name'
                }
            }
        ]
        all_teachers = list(teachers_collection.aggregate(pipeline))
        for t in all_teachers:
            t['_id'] = str(t['_id'])
        return jsonify(all_teachers)
    except Exception as e:
        return jsonify({"message": f"An error occurred: {str(e)}"}), 500

# NEW ROUTE: Admin can delete any student
@app.route("/api/admin/students/<student_id>", methods=["DELETE"])
@admin_token_required
def admin_delete_student(current_admin, student_id):
    result = students_collection.delete_one({'_id': ObjectId(student_id)})
    if result.deleted_count:
        return jsonify({"message": "Student deleted successfully"})
    return jsonify({"message": "Student not found"}), 404

# NEW ROUTE: Admin can delete any teacher
@app.route("/api/admin/teachers/<teacher_id>", methods=["DELETE"])
@admin_token_required
def admin_delete_teacher(current_admin, teacher_id):
    result = teachers_collection.delete_one({'_id': ObjectId(teacher_id)})
    if result.deleted_count:
        return jsonify({"message": "Teacher deleted successfully"})
    return jsonify({"message": "Teacher not found"}), 404


# ... (keep all your other routes) ...

# --- 6. DATA MANAGEMENT ROUTES (SECURED) ---
@app.route("/api/profile", methods=["GET", "PUT"])
@token_required
def profile_route(current_user):
    if request.method == "GET":
        current_user['_id'] = str(current_user['_id'])
        if 'password' in current_user: del current_user['password']
        return jsonify(current_user)
    elif request.method == "PUT":
        data = request.get_json()
        if 'password' in data: del data['password']
        users_collection.update_one({'_id': current_user['_id']}, {'$set': data })
        return jsonify({"message": "Profile updated successfully"})

@app.route("/api/teachers", methods=["GET", "POST"])
@token_required
def teachers_route(current_user):
    school_id = current_user['_id']
    if request.method == "GET":
        teachers = list(teachers_collection.find({"school_id": school_id}))
        for t in teachers:
            t['_id'] = str(t['_id'])
            if 'school_id' in t: t['school_id'] = str(t['school_id'])
        return jsonify(teachers)
    elif request.method == "POST":
        data = request.get_json()
        data['school_id'] = school_id
        teachers_collection.insert_one(data)
        return jsonify({"message": "Teacher added successfully"}), 201

@app.route("/api/teachers/<teacher_id>", methods=["PUT", "DELETE"])
@token_required
def single_teacher_route(current_user, teacher_id):
    query = {'_id': ObjectId(teacher_id), 'school_id': current_user['_id']}
    if request.method == "PUT":
        result = teachers_collection.update_one(query, {'$set': request.get_json()})
        return jsonify({"message": "Teacher updated"}) if result.matched_count else ({"message": "Teacher not found or access denied"}, 404)
    elif request.method == "DELETE":
        result = teachers_collection.delete_one(query)
        return jsonify({"message": "Teacher deleted"}) if result.deleted_count else ({"message": "Teacher not found or access denied"}, 404)

@app.route("/api/students", methods=["GET", "POST"])
@token_required
def students_route(current_user):
    school_id = current_user['_id']
    if request.method == "GET":
        students = list(students_collection.find({"school_id": school_id}))
        for s in students:
            s['_id'] = str(s['_id'])
            if 'school_id' in s: s['school_id'] = str(s['school_id'])
        return jsonify(students)
    elif request.method == "POST":
        data = request.get_json()
        data['school_id'] = school_id
        students_collection.insert_one(data)
        return jsonify({"message": "Student added successfully"}), 201

@app.route("/api/students/<student_id>", methods=["PUT", "DELETE"])
@token_required
def single_student_route(current_user, student_id):
    query = {'_id': ObjectId(student_id), 'school_id': current_user['_id']}
    if request.method == "PUT":
        result = students_collection.update_one(query, {'$set': request.get_json()})
        return jsonify({"message": "Student updated"}) if result.matched_count else ({"message": "Student not found or access denied"}, 404)
    elif request.method == "DELETE":
        result = students_collection.delete_one(query)
        return jsonify({"message": "Student deleted"}) if result.deleted_count else ({"message": "Student not found or access denied"}, 404)

# --- 7. FEEDBACK & NOTIFICATION ROUTES ---
@app.route("/api/feedback", methods=["POST"])
@token_required
def submit_feedback(current_user):
    data = request.get_json()
    feedback_collection.insert_one({
        "user_id": current_user["_id"], "username": current_user["username"],
        "school_name": current_user.get("school_name", "N/A"), "subject": data.get("subject"),
        "message": data.get("message"), "submitted_at": datetime.now(timezone.utc)
    })
    return jsonify({"message": "Feedback submitted successfully"}), 201

# --- NEW ROUTE FOR USERS TO GET NOTIFICATIONS ---
@app.route("/api/notifications", methods=["GET"])
@token_required
def get_notifications(current_user):
    # This route allows any logged-in user to see all broadcasted notifications
    notifications = list(notifications_collection.find({}).sort("timestamp", -1))
    for n in notifications:
        n['_id'] = str(n['_id'])
    return jsonify(notifications)

# --- 8. ADMIN-ONLY ROUTES ---
@app.route("/api/admin/dashboard-data", methods=["GET"])
@admin_token_required
def get_dashboard_data(current_admin):
    school_count = users_collection.count_documents({})
    feedback_count = feedback_collection.count_documents({})
    all_schools = list(users_collection.find({}, {"password": 0}))
    for s in all_schools: s['_id'] = str(s['_id'])
    return jsonify({ "stats": { "school_count": school_count, "feedback_count": feedback_count }, "schools": all_schools })

@app.route("/api/admin/feedback", methods=["GET"])
@admin_token_required
def get_all_feedback(current_admin):
    feedbacks = list(feedback_collection.find({}).sort("submitted_at", -1))
    for f in feedbacks: f['_id'] = str(f['_id']); f['user_id'] = str(f['user_id'])
    return jsonify(feedbacks)
    
@app.route("/api/admin/feedback/reply/<feedback_id>", methods=["POST"])
@admin_token_required
def reply_to_feedback(current_admin, feedback_id):
    print(f"Admin '{current_admin['username']}' replied to feedback {feedback_id}")
    return jsonify({"message": "Reply sent successfully (simulated)"})

@app.route("/api/admin/notifications", methods=["POST"])
@admin_token_required
def send_notification(current_admin):
    data = request.get_json()
    notifications_collection.insert_one({
        "message": data.get('message'),
        "subject": data.get('subject'), # Saving subject now
        "timestamp": datetime.now(timezone.utc),
        "sent_by": current_admin['username']
    })
    return jsonify({"message": "Notification sent successfully"}), 201

@app.route("/api/admin/users/<user_id>", methods=["DELETE"])
@admin_token_required
def delete_user(current_admin, user_id):
    school_id_to_delete = ObjectId(user_id)
    user_result = users_collection.delete_one({'_id': school_id_to_delete})
    if user_result.deleted_count == 0:
        return jsonify({"message": "School user not found"}), 404
    teacher_result = teachers_collection.delete_many({'school_id': school_id_to_delete})
    student_result = students_collection.delete_many({'school_id': school_id_to_delete})
    return jsonify({
        "message": "School and all associated data deleted successfully",
        "teachers_deleted": teacher_result.deleted_count,
        "students_deleted": student_result.deleted_count
    }), 200

# --- 9. FRONTEND SERVING ROUTES ---
@app.route('/')
@no_cache
def serve_index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/admin/login')
@no_cache
def serve_admin_login():
    return send_from_directory(app.static_folder, 'admin_login.html')

@app.route('/<path:path>')
@no_cache
def serve_static_files(path):
    return send_from_directory(app.static_folder, path)

# --- 10. SERVER EXECUTION ---
if __name__ == "__main__":
    app.run(debug=True, port=5001, host="0.0.0.0")