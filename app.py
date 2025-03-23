from flask import Flask, jsonify, request
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_talisman import Talisman
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)

app.config['SECRET_KEY'] = 'replace-with-a-very-strong-secret-key'

environ = os.environ.get('FLASK_ENV', 'production')

# COOKIE SETTINGS - After making a response: response = make_response(jsonify({})), set the cookie like this:
# response.set_cookie(
#     'auth_token',
#     token,
#     httponly=True,
#     secure=True,
#     samesite='None',
#     max_age=1209600 # 2 weeks in seconds
# )

csrf = CSRFProtect(app)

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    response = jsonify({'csrf_token': token})
    response.headers.set('X-CSRFToken', token)
    return response

csp = {
    'default-src': ["'self'"],
    'connect-src': ["'self'"],
    'object-src': ["'none'"]
}
Talisman(
    app,
    content_security_policy=csp,
    frame_options='DENY',
    force_https=environ not in ['development', 'test'],
    strict_transport_security=True, # HSTS
    strict_transport_security_preload=True,
    session_cookie_secure=True,
    session_cookie_http_only=True
)

CORS(app, 
     supports_credentials=True, 
     origins=['https://frontend-domain.com'],
     expose_headers=['Content-Type', 'X-CSRFToken'],
     allow_headers=['Content-Type', 'X-CSRFToken', 'Authorization'])

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379/0"
)
limiter.init_app(app)

@app.before_request
def validate_content_type():
    if request.method in ['POST', 'PUT', 'PATCH'] and request.path != '/api/csrf-token':
        if not request.is_json and 'multipart/form-data' not in request.content_type:
            return jsonify({'error': 'Content-Type must be application/json or multipart/form-data'}), 415

@app.before_request
def security_checks():
    for key, value in request.values.items():
        if isinstance(value, str):
            if '<script>' in value.lower():
                return jsonify({'error': 'Invalid input detected'}), 400

@app.errorhandler(404)
def page_not_found(e):
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify({"status": "success", "data": {"message": "This is API data"}})

@app.route('/api/submit', methods=['POST'])
def submit_data():
    if not request.is_json:
        return jsonify({"error": "Request must be JSON"}), 400
    
    data = request.get_json()
    # Process data here
    
    return jsonify({"status": "success", "received": data})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=environ == 'development')
