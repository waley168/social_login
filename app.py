from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_oauthlib.provider import OAuth2Provider
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
oauth = OAuth2Provider(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    clients = db.relationship('Client', backref='user', lazy=True)

class Client(db.Model):
    id = db.Column(db.String(40), primary_key=True)
    secret = db.Column(db.String(55), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    _redirect_uris = db.Column(db.Text)
    _default_scopes = db.Column(db.Text)

    @property
    def client_id(self):
        return self.id

    @property
    def client_secret(self):
        return self.secret

    @property
    def redirect_uris(self):
        return self._redirect_uris.split()

    @property
    def default_scopes(self):
        return self._default_scopes.split()

class Grant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    client_id = db.Column(db.String(40), db.ForeignKey('client.id'))
    code = db.Column(db.String(255), index=True, nullable=False)
    redirect_uri = db.Column(db.String(255))
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    def delete(self):
        db.session.delete(self)
        db.session.commit()
        return self

    @property
    def scopes(self):
        return self._scopes.split()

class Token(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(40), db.ForeignKey('client.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    expires = db.Column(db.DateTime)
    _scopes = db.Column(db.Text)

    @property
    def scopes(self):
        return self._scopes.split()
    
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@oauth.clientgetter
def load_client(client_id):
    return Client.query.filter_by(id=client_id).first()

@oauth.grantgetter
def load_grant(client_id, code):
    return Grant.query.filter_by(client_id=client_id, code=code).first()

@oauth.grantsetter
def save_grant(client_id, code, request, *args, **kwargs):
    expires = datetime.utcnow() + timedelta(seconds=100)
    grant = Grant(
        client_id=client_id,
        code=code['code'],
        redirect_uri=request.redirect_uri,
        _scopes=' '.join(request.scopes),
        user=current_user,
        expires=expires
    )
    db.session.add(grant)
    db.session.commit()
    return grant

@oauth.tokengetter
def load_token(access_token=None, refresh_token=None):
    if access_token:
        return Token.query.filter_by(access_token=access_token).first()
    if refresh_token:
        return Token.query.filter_by(refresh_token=refresh_token).first()

@oauth.tokensetter
def save_token(token, request, *args, **kwargs):
    expires_in = token.pop('expires_in')
    expires = datetime.utcnow() + timedelta(seconds=expires_in)

    tok = Token(**token)
    tok.expires = expires
    tok.client_id = request.client.id
    tok.user_id = request.user.id

    db.session.add(tok)
    db.session.commit()
    return tok

@app.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize(*args, **kwargs):
    if request.method == 'GET':
        client_id = request.args.get('client_id')
        client = Client.query.filter_by(id=client_id).first()
        kwargs['client'] = client
        return render_template('authorize.html', **kwargs)

    confirm = request.form.get('confirm', 'no')
    return 'confirm' if confirm == 'yes' else 'deny'

@app.route('/oauth/token', methods=['POST'])
@oauth.token_handler
def access_token():
    return None

@app.route('/api/userinfo')
@oauth.require_oauth()
def userinfo():
    user = request.oauth.user
    return jsonify(username=user.username, user_id=user.id)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
