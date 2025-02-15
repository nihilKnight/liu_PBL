from flask import Flask, render_template, jsonify, request, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

import random
import string
from captcha.image import ImageCaptcha
import os

from dotenv import load_dotenv

from flask_mail import Mail, Message
from email_validator import validate_email, EmailNotValidError

import random
from datetime import datetime, timedelta

from flask_limiter import Limiter

load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 添加邮件配置
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
# 调试模式下
# app.config['MAIL_SUPPRESS_SEND'] = True
# app.config['MAIL_DEBUG'] = True
# app.config['MAIL_DEFAULT_SENDER'] = 'debug@example.com'

db = SQLAlchemy(app)

mail = Mail(app)

limiter = Limiter(app=app, key_func=lambda: request.remote_addr)

def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(200))

# 添加验证码存储模型
class VerificationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

# 图形验证码生成
@app.route('/captcha')
def generate_captcha():
    captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4))
    session['captcha'] = captcha_text
    data = ImageCaptcha().generate(captcha_text)
    return Response(data, content_type='image/png')

@app.route('/')
def index():
    if 'user' in session:
        return render_template('index.html')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # 登录验证逻辑
        return render_template('index.html')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user_code = request.form.get('verification_code', '')
        
        # 验证验证码
        valid_code = VerificationCode.query.filter(
            VerificationCode.email == email,
            VerificationCode.code == user_code,
            VerificationCode.created_at >= datetime.now() - timedelta(minutes=5)
        ).first()
        
        if not valid_code:
            return render_template('register.html', error="验证码错误或已过期")
        
        # 验证邮箱唯一性
        if User.query.filter_by(email=email).first():
            return render_template('register.html', error="该邮箱已被注册")
            
        # 创建新用户
        new_user = User(
            email=email,
            password=generate_password_hash(password)
        )
        db.session.add(new_user)
        
        # 删除已使用的验证码
        db.session.delete(valid_code)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/send_verification_code', methods=['POST'])
@limiter.limit("5/hour")  # 同一IP每小时最多5次
def send_verification_code():
    data = request.get_json()
    email = data.get('email', '').strip()
    
    try:
        # 验证邮箱格式
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError:
        return jsonify({'success': False, 'message': '无效的邮箱地址'})
    
    # 生成验证码
    code = generate_verification_code()
    
    # 存储验证码（先删除旧验证码）
    VerificationCode.query.filter_by(email=email).delete()
    new_code = VerificationCode(email=email, code=code)
    db.session.add(new_code)
    db.session.commit()
    
    # 发送邮件
    try:
        msg = Message(
            subject="您的注册验证码",
            recipients=[email],
            html='email_template.html',
        )
        mail.send(msg)
        return jsonify({'success': True})
    except Exception as e:
        print(f"邮件发送失败: {str(e)}")
        return jsonify({'success': False, 'message': '邮件发送失败'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)