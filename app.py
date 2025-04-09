import eventlet
eventlet.monkey_patch()

from flask import Flask, render_template, request, redirect, url_for, make_response
from authlib.integrations.flask_client import OAuth
from flask_socketio import SocketIO
import sqlite3
import qrcode
import os
from datetime import datetime
import jwt
import base64
import io
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv('JWT_SECRET', 'your_jwt_secret_key')
JWT_ALGORITHM = 'HS256'
LOCALHOST = os.getenv('LOCALHOST', 'localhost')


app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET','your_secret_key')
app.config['GOOGLE_CLIENT_ID'] = '13667574086-7rqtc0alheampic4fkjrid6b55hd9791.apps.googleusercontent.com'
app.config['GOOGLE_CLIENT_SECRET'] = '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'
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"

socketio = SocketIO(app)

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
    client_kwargs={
        'scope': 'openid email profile',
    }
)


def decode_jwt_from_request():
    token = request.cookies.get('access_token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# Initialize DB
def init_db():
    with sqlite3.connect("attendance.db") as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                date_created TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                student_name TEXT,
                reg_no TEXT,
                timestamp TEXT,
                ip_address TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )
        ''')

init_db()

@app.route('/')
def index():
    with sqlite3.connect("attendance.db") as conn:
        sessions = conn.execute("SELECT id, name, date_created FROM sessions ORDER BY date_created DESC").fetchall()
    return render_template('index.html', sessions=sessions)

@app.route('/create_session', methods=['GET', 'POST'])
def create_session():
    if request.method == 'POST':
        session_name = request.form['session_name']
        date_created = datetime.now().isoformat()

        with sqlite3.connect("attendance.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO sessions (name, date_created) VALUES (?, ?)", (session_name, date_created))
            session_id = cursor.lastrowid

            # Generate QR Code in memory
            qr_url = f'http://{LOCALHOST}:5000/attend/{session_id}'

            img = qrcode.make(qr_url)
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            buffer.seek(0)

            # Encode to Base64
            img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            qr_data_uri = f"data:image/png;base64,{img_base64}"

        return render_template('generate_qr.html', qr_data_uri=qr_data_uri, session_id=session_id)

    return render_template('create_session.html')

@app.route('/attend/<int:session_id>', methods=['GET', 'POST'])
def attend(session_id):
    userinfo = decode_jwt_from_request()

    if not userinfo:
        login_url = url_for('auth', next=url_for('attend', session_id=session_id, _external=True))
        return render_template('login_prompt.html', login_url=login_url, session_id=session_id)

    firstname = userinfo['firstname']
    lastname = userinfo['lastname']

    if request.method == 'POST':
        student_name = userinfo['firstname']
        reg_no = userinfo['lastname']
        timestamp = datetime.now().isoformat()
        ip_address = request.remote_addr

        with sqlite3.connect("attendance.db") as conn:
            conn.execute(
                "INSERT INTO attendance (session_id, student_name, reg_no, timestamp, ip_address) VALUES (?, ?, ?, ?, ?)",
                (session_id, student_name, reg_no, timestamp, ip_address)
            )

        socketio.emit('new_attendance', {
            'student_name': student_name,
            'reg_no': reg_no,
            'timestamp': timestamp,
            'ip_address': ip_address,
            'session_id': session_id
        })

        return render_template('attendance_marked.html', session_id=session_id, student_name=student_name)

    return render_template('attendance_form.html', session_id=session_id, student_name=firstname, reg_no=lastname)


@app.route('/session/<int:session_id>')
def session_view(session_id):
    with sqlite3.connect("attendance.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sessions WHERE id = ?", (session_id,))
        session_name = cur.fetchone()[0]
        attendees = cur.execute(
            "SELECT student_name, reg_no, timestamp, ip_address FROM attendance WHERE session_id = ?", (session_id,)
        ).fetchall()
    return render_template('session_view.html', session_name=session_name, session_id=session_id, attendees=attendees)

@app.route('/auth')
def auth():
    next_url = request.args.get('next', '/')
    redirect_uri = url_for('callback', _external=True)
    return google.authorize_redirect(redirect_uri, state=next_url)



@app.route('/callback')
def callback():
    token = google.authorize_access_token()
    userinfo = google.get('https://openidconnect.googleapis.com/v1/userinfo').json()

    firstname = userinfo.get("given_name")
    lastname = userinfo.get("family_name")
    next_url = request.args.get('state', '/')

    # Create JWT payload
    payload = {
        'firstname': firstname,
        'lastname': lastname,
        'iat': datetime.utcnow().timestamp()
    }
    jwt_token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Set JWT in cookie
    resp = make_response(redirect(next_url))
    resp.set_cookie('access_token', jwt_token, httponly=True, secure=True, samesite='Lax')
    return resp

@app.route('/logout')
def logout():
    resp = make_response(redirect('/'))
    resp.set_cookie('access_token', '', expires=0)
    return resp


@socketio.on('connect')
def handle_connect():
    print('📡 Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('❌ Client disconnected')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
