"""
Mini Réseau Social avec Flask

Fonctionnalités:
- Inscription (nom d'utilisateur, email, mot de passe hashé)
- Connexion/Déconnexion
- Profil utilisateur avec biographie modifiable
- Recherche d'autres utilisateurs
- Système d'amis (demandes d'amis, acceptation)
- Messagerie privée entre amis

Base de données: SQLite
Interface: HTML/CSS basique

Pour exécuter:
1. pip install -r requirements.txt
2. python app.py
3. Accédez à http://localhost:5000
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete_super_secrete'

# Configuration de la base de données
DATABASE = 'social_network.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with app.app_context():
        db = get_db()
        # Création des tables si elles n'existent pas
        db.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            bio TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        db.execute('''
        CREATE TABLE IF NOT EXISTS friendships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            friend_id INTEGER NOT NULL,
            status TEXT NOT NULL, -- 'pending' or 'accepted'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (friend_id) REFERENCES users (id),
            UNIQUE(user_id, friend_id)
        )
        ''')
        
        db.execute('''
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

# Routes de l'application
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    
    # Récupérer les amis
    friends = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON (friendships.friend_id = users.id AND friendships.user_id = ? AND friendships.status = 'accepted')
    OR (friendships.user_id = users.id AND friendships.friend_id = ? AND friendships.status = 'accepted')
    ''', (session['user_id'], session['user_id'])).fetchall()
    
    # Récupérer les demandes d'amis reçues
    friend_requests = db.execute('''
    SELECT users.id, users.username FROM users 
    JOIN friendships ON friendships.user_id = users.id 
    WHERE friendships.friend_id = ? AND friendships.status = 'pending'
    ''', (session['user_id'],)).fetchall()
    
    # Récupérer les messages non lus
    unread_messages = db.execute('''
    SELECT COUNT(*) as count FROM messages 
    WHERE receiver_id = ? AND is_read = FALSE
    ''', (session['user_id'],)).fetchone()['count']
    
    return render_template('index.html', user=user, friends=friends, friend_requests=friend_requests, unread_messages=unread_messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                       (username, email, hashed_password))
            db.commit()
            flash('Inscription réussie! Vous pouvez maintenant vous connecter.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Nom d\'utilisateur ou email déjà utilisé', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

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
    
    return render_template('login.html')

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
    return render_template('profile.html', user=user)

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
    
    return render_template('search.html', results=results)

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
    
    return render_template('friends.html', 
                         friends=friends, 
                         sent_requests=sent_requests, 
                         received_requests=received_requests)

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
    
    return render_template('messages.html', 
                         friends=friends, 
                         messages=messages, 
                         current_friend_id=friend_id)

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
    app.run(debug=True)