from flask import Flask, request, session, redirect, url_for, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'ton_secret_key_ici'
DATABASE = 'database.db'

# Style CSS commun à toutes les pages
COMMON_CSS = """
<style>
    body {
        font-family: Arial, sans-serif;
        max-width: 800px;
        margin: 0 auto;
        padding: 20px;
        line-height: 1.6;
    }
    h1, h2 {
        color: #333;
    }
    form {
        margin: 20px 0;
    }
    input, textarea, button {
        padding: 8px;
        margin: 5px 0;
    }
    button {
        background: #007bff;
        color: white;
        border: none;
        cursor: pointer;
    }
    button:hover {
        background: #0056b3;
    }
    .flash-message {
        padding: 10px;
        margin: 10px 0;
        border-radius: 4px;
    }
    .success {
        background: #d4edda;
        color: #155724;
    }
    .error {
        background: #f8d7da;
        color: #721c24;
    }
    .info {
        background: #e2e3e5;
        color: #383d41;
    }
    ul {
        list-style: none;
        padding: 0;
    }
    li {
        padding: 8px;
        border-bottom: 1px solid #eee;
    }
    .conversation {
        border: 1px solid #ccc;
        padding: 10px;
        height: 300px;
        overflow-y: scroll;
        margin-bottom: 10px;
    }
</style>
"""

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Création des tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (friend_id) REFERENCES users (id),
            CHECK (user_id != friend_id),
            CHECK (status IN ('pending', 'accepted', 'rejected'))
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )
        ''')
        
        db.commit()

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Accueil</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Bienvenue, {user['username']}!</h1>
        
        <!-- Affichage des messages flash -->
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <nav>
            <ul>
                <li><a href="/profile">Mon profil</a></li>
                <li><a href="/friends">Amis</a></li>
                <li><a href="/search">Rechercher des amis</a></li>
                <li><a href="/logout">Déconnexion</a></li>
            </ul>
        </nav>
        
        <h2>Dernières activités</h2>
        <p>Contenu de la page d'accueil...</p>
    </body>
    </html>
    """

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        error = None
        
        if not username:
            error = 'Un nom d\'utilisateur est requis'
        elif not password:
            error = 'Un mot de passe est requis'
        elif db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            error = f"L'utilisateur {username} existe déjà."
        
        if error is None:
            db.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            db.commit()
            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        
        flash(error, 'error')
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Inscription</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Inscription</h1>
        
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <form method="POST">
            <p>Nom d'utilisateur: <input type="text" name="username" required></p>
            <p>Mot de passe: <input type="password" name="password" required></p>
            <button type="submit">S'inscrire</button>
        </form>
        <p>Déjà un compte? <a href="/login">Connectez-vous</a></p>
    </body>
    </html>
    """

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Connexion réussie!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
            return redirect(url_for('login'))
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Connexion</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Connexion</h1>
        
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <form method="POST">
            <p>Nom d'utilisateur: <input type="text" name="username" required></p>
            <p>Mot de passe: <input type="password" name="password" required></p>
            <button type="submit">Se connecter</button>
        </form>
        <p>Pas encore de compte? <a href="/register">Inscrivez-vous</a></p>
    </body>
    </html>
    """

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    if request.method == 'POST':
        bio = request.form['bio']
        db.execute('UPDATE users SET bio = ? WHERE id = ?', (bio, session['user_id']))
        db.commit()
        flash('Profil mis à jour!', 'success')
        return redirect(url_for('profile'))
    
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Profil</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Profil de {user['username']}</h1>
        
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <form method="POST">
            <p>Bio:</p>
            <textarea name="bio" rows="4" cols="50">{user.get('bio', '')}</textarea>
            <br>
            <button type="submit">Mettre à jour</button>
        </form>
        <p><a href="/">Retour à l'accueil</a></p>
    </body>
    </html>
    """

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    results = []
    
    if request.method == 'POST':
        search_term = f"%{request.form['search_term']}%"
        results = db.execute('''
        SELECT id, username, bio FROM users 
        WHERE username LIKE ? AND id != ?
        ''', (search_term, session['user_id'])).fetchall()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Recherche</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Rechercher des amis</h1>
        
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <form method="POST">
            <input type="text" name="search_term" placeholder="Nom d'utilisateur" required>
            <button type="submit">Rechercher</button>
        </form>
    """
    
    if results:
        html += "<h2>Résultats:</h2><ul>"
        for user in results:
            html += f"""
            <li>
                {user['username']} - {user.get('bio', '')}
                <a href="/add_friend/{user['id']}">Ajouter comme ami</a>
            </li>
            """
        html += "</ul>"
    
    html += """
        <p><a href="/">Retour à l'accueil</a></p>
    </body>
    </html>
    """
    
    return html

@app.route('/add_friend/<int:friend_id>')
def add_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Vérifier si la demande d'ami existe déjà
    existing = db.execute('''
    SELECT * FROM friendships 
    WHERE (user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)
    ''', (session['user_id'], friend_id, friend_id, session['user_id'])).fetchone()
    
    if existing:
        flash('Demande d\'ami déjà envoyée ou déjà ami', 'info')
    else:
        db.execute('''
        INSERT INTO friendships (user_id, friend_id, status) 
        VALUES (?, ?, 'pending')
        ''', (session['user_id'], friend_id))
        db.commit()
        flash('Demande d\'ami envoyée!', 'success')
    
    return redirect(url_for('search'))

@app.route('/accept_friend/<int:friend_id>')
def accept_friend(friend_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Vérifier que la demande existe et est en attente
    request_exists = db.execute('''
    SELECT * FROM friendships 
    WHERE user_id = ? AND friend_id = ? AND status = 'pending'
    ''', (friend_id, session['user_id'])).fetchone()
    
    if request_exists:
        db.execute('''
        UPDATE friendships SET status = 'accepted' 
        WHERE user_id = ? AND friend_id = ?
        ''', (friend_id, session['user_id']))
        db.commit()
        flash('Demande d\'ami acceptée!', 'success')
    else:
        flash('Demande d\'ami non trouvée', 'error')
    
    return redirect(url_for('index'))

@app.route('/friends')
def friends():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Amis acceptés
    friends = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON (friendships.friend_id = users.id AND friendships.user_id = ? AND friendships.status = 'accepted')
    OR (friendships.user_id = users.id AND friendships.friend_id = ? AND friendships.status = 'accepted')
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    # Demandes envoyées en attente
    sent_requests = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON friendships.friend_id = users.id 
    WHERE friendships.user_id = ? AND friendships.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    
    # Demandes reçues en attente
    received_requests = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON friendships.user_id = users.id 
    WHERE friendships.friend_id = ? AND friendships.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Amis</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Vos amis</h1>
        
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <h2>Amis ({len(friends)})</h2>
        <ul>
    """
    
    for friend in friends:
        html += f"""
            <li>
                {friend['username']}
                <a href="/messages?friend_id={friend['id']}">Message</a>
            </li>
        """
    
    html += """
        </ul>
        
        <h2>Demandes envoyées ({len(sent_requests)})</h2>
        <ul>
    """
    
    for req in sent_requests:
        html += f"<li>{req['username']} (en attente)</li>"
    
    html += """
        </ul>
        
        <h2>Demandes reçues ({len(received_requests)})</h2>
        <ul>
    """
    
    for req in received_requests:
        html += f"""
            <li>
                {req['username']}
                <a href="/accept_friend/{req['id']}">Accepter</a>
            </li>
        """
    
    html += """
        </ul>
        <p><a href="/">Retour à l'accueil</a></p>
    </body>
    </html>
    """
    
    return html

@app.route('/messages')
def messages():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    friend_id = request.args.get('friend_id', type=int)
    
    # Liste des amis pour le menu
    friends = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON (friendships.friend_id = users.id AND friendships.user_id = ? AND friendships.status = 'accepted')
    OR (friendships.user_id = users.id AND friendships.friend_id = ? AND friendships.status = 'accepted')
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    messages = []
    if friend_id:
        # Marquer les messages comme lus
        db.execute('''
        UPDATE messages SET is_read = TRUE 
        WHERE sender_id = ? AND receiver_id = ? AND is_read = FALSE
        ''', (friend_id, session['user_id']))
        db.commit()
        
        # Récupérer la conversation
        messages = db.execute('''
        SELECT m.*, u.username as sender_name FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at
        ''', (session['user_id'], friend_id, friend_id, session['user_id'])).fetchall()
    
    # Trouver le nom de l'ami actuel
    current_friend_name = None
    if friend_id:
        for friend in friends:
            if friend['id'] == friend_id:
                current_friend_name = friend['username']
                break
    
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Messages</title>
        {COMMON_CSS}
    </head>
    <body>
        <h1>Messages</h1>
        
        {'<div class="flash-message ' + category + '">' + message + '</div>' 
         for category, message in get_flashed_messages(with_categories=True)}
        
        <div style="display: flex;">
            <div style="width: 30%;">
                <h2>Amis</h2>
                <ul>
    """
    
    for friend in friends:
        html += f"""
                    <li>
                        <a href="/messages?friend_id={friend['id']}">{friend['username']}</a>
                    </li>
        """
    
    html += """
                </ul>
            </div>
            
            <div style="width: 70%;">
    """
    
    if friend_id:
        html += f"""
                <h2>Conversation avec {current_friend_name}</h2>
                <div class="conversation">
        """
        
        for msg in messages:
            html += f"""
                    <div style="margin-bottom: 10px; {'text-align: right;' if msg['sender_id'] == session['user_id'] else ''}">
                        <strong>{msg['sender_name']}</strong> ({msg['created_at']})<br>
                        {msg['content']}
                    </div>
            """
        
        html += """
                </div>
                
                <form method="POST" action="/send_message">
                    <input type="hidden" name="friend_id" value="{friend_id}">
                    <textarea name="content" rows="3" style="width: 100%;" required></textarea>
                    <button type="submit">Envoyer</button>
                </form>
        """
    else:
        html += "<p>Sélectionnez un ami pour voir la conversation</p>"
    
    html += """
            </div>
        </div>
        
        <p><a href="/">Retour à l'accueil</a></p>
    </body>
    </html>
    """
    
    return html

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    friend_id = request.form['friend_id']
    content = request.form['content']
    
    if not content:
        flash('Le message ne peut pas être vide', 'error')
        return redirect(url_for('messages', friend_id=friend_id))
    
    db = get_db()
    
    # Vérifier que les utilisateurs sont amis
    are_friends = db.execute('''
    SELECT * FROM friendships 
    WHERE ((user_id = ? AND friend_id = ?) OR (user_id = ? AND friend_id = ?)) 
    AND status = 'accepted'
    ''', (session['user_id'], friend_id, friend_id, session['user_id'])).fetchone()
    
    if not are_friends:
        flash('Vous ne pouvez envoyer des messages qu\'à vos amis', 'error')
        return redirect(url_for('messages', friend_id=friend_id))
    
    db.execute('''
    INSERT INTO messages (sender_id, receiver_id, content) 
    VALUES (?, ?, ?)
    ''', (session['user_id'], friend_id, content))
    db.commit()
    
    return redirect(url_for('messages', friend_id=friend_id))

if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)
