from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import random
from PIL import Image, ImageDraw, ImageFont, ImageFilter
import random, string, io
from sqlalchemy import text, or_
from flask_migrate import Migrate
from math import ceil
import pandas as pd
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import io
from sqlalchemy.sql import func, case, asc, desc
from flask import render_template, make_response, jsonify
from flask_apscheduler import APScheduler
import pytz
from pytz import timezone
from sqlalchemy.orm import joinedload

ALLOWED_EXTENSIONS = {'xls', 'xlsx'}

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/vjr_new'
#app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:Vjr%401234567890@localhost/vjr_new'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False 
app.config['MAX_CONTENT_LENGTH'] = 150 * 1024 * 1024
app.config['SECRET_KEY'] = 'b35dfe6ce150230940bd145823034486' 

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Config:
    SCHEDULER_API_ENABLED = True

app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

@scheduler.task('cron', id='increment_overdue', hour=0, minute=0, timezone='Asia/Jakarta')
def increment_overdue():
    with app.app_context():
        all_data = Data.query.all()
        for d in all_data:
            if d.overdue and d.overdue.isdigit():
                d.overdue = str(int(d.overdue) + 1)
            else:
                d.overdue = "1"
        db.session.commit()
        print(f"[{datetime.now(timezone('Asia/Jakarta')).strftime('%Y-%m-%d %H:%M:%S')}] Overdue berhasil ditambah.")

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    id_system = db.Column(db.String(255))
    username = db.Column(db.String(255))
    phone = db.Column(db.String(15))
    email = db.Column(db.String(255))
    group = db.Column(db.Integer, db.ForeignKey('user_group.id'))  
    status = db.Column(db.String(10), default='active')
    password = db.Column(db.String(255))
    role = db.Column(db.String(50))
    num_sip = db.Column(db.String(255))
    pas_sip = db.Column(db.String(255))
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)

    group_rel = db.relationship('UserGroup', backref=db.backref('users', lazy=True))
    data = db.relationship('Data', backref='user', lazy=True, passive_deletes=True)

    def is_online(self):
        return self.last_seen and self.last_seen >= datetime.utcnow() - timedelta(minutes=5)
    
    def last_seen_ago(self):
        if not self.last_seen:
            return "N/A"
        delta = datetime.utcnow() - self.last_seen
        seconds = int(delta.total_seconds())

        if seconds < 60:
            return "Baru saja"
        minutes = seconds // 60
        if minutes < 60:
            if minutes == 1:
                return "1 menit lalu"
            return f"{minutes} menit lalu"
        hours = minutes // 60
        if hours < 24:
            if hours == 1:
                return "1 jam lalu"
            return f"{hours} jam lalu"
        days = hours // 24
        if days == 1:
            return "1 hari lalu"
        return f"{days} hari lalu"

class UserGroup(db.Model):  
    __tablename__ = 'user_group' 
    id = db.Column(db.Integer, primary_key=True)
    company = db.Column(db.String(255))
    status = db.Column(db.String(10), default='active')
    overdue = db.Column(db.String(50))
    logo = db.Column(db.String(255))

class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_no = db.Column(db.String(50))
    nama_nasabah = db.Column(db.String(255))
    alamat = db.Column(db.Text)
    pekerjaan = db.Column(db.String(255))
    waktu_peminjaman = db.Column(db.String(255))
    exp_date = db.Column(db.Date)
    phone = db.Column(db.String(255))
    pokok_pinjaman = db.Column(db.String(255))
    total_tagihan = db.Column(db.String(255))
    overdue = db.Column(db.String(255))
    nama_ec1 = db.Column(db.String(255))
    nomor_ec1 = db.Column(db.String(255))
    nama_ec2 = db.Column(db.String(255))
    phone_ec2 = db.Column(db.String(255))
    tanggal_upload = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'))
    remark = db.Column(db.String(255), default='1')
    catatan = db.Column(db.Text)
    optional_1 = db.Column(db.Text)
    optional_2 = db.Column(db.Text)
    optional_3 = db.Column(db.Text)
    optional_4 = db.Column(db.Text)

class UserLoginLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    user = db.relationship('User', backref=db.backref('login_logs', lazy=True))

class UserActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    activity = db.Column(db.String(255))
    route = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('activities', lazy=True))

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@app.context_processor
def inject_users_status():
    threshold = datetime.utcnow() - timedelta(minutes=5)

    online_status = case(
        (User.last_seen >= threshold, 1),
        else_=0
    )
    users = User.query.filter_by(role="user") \
        .order_by(desc(online_status), desc(User.last_seen)) \
        .all()

    online_users = [u for u in users if u.is_online()]

    return dict(
        all_users=users,
        online_users_count=len(online_users)
    )   

@scheduler.task('cron', id='delete_expired_data', hour=0)
def delete_expired_data():
    today = datetime.now().date()
    expired_data = Data.query.filter(Data.exp_date < today).all()
    
    for data in expired_data:
        db.session.delete(data)
    
    db.session.commit()
    print(f"[Scheduler] {len(expired_data)} data dengan exp_date <= {today} berhasil dihapus otomatis.")

@scheduler.task('cron', id='delete_orphan_data', hour=0)
def delete_orphan_data():
    with app.app_context():
        orphan_data = Data.query.filter(Data.user_id == None).all()
        
        if orphan_data:
            for data in orphan_data:
                db.session.delete(data)
            db.session.commit()
            print(f"[Orphan Cleaner] {len(orphan_data)} data tanpa user_id dihapus.")

@app.before_request
def log_user_activity():
    if current_user.is_authenticated and current_user.role == 'user':
        ignored_routes = ['/login']

        if any(request.path.startswith(ignored) for ignored in ignored_routes):
            return 
        
        current_route = request.path
        print(f"{current_route}")

        activity_log = f"{current_route}"
        
        new_activity = UserActivity(
            user_id=current_user.id,
            activity=activity_log,
            route=current_route
        )
        db.session.add(new_activity)

        try:
            db.session.commit() 
        except Exception as e:
            db.session.rollback()
            print(f"Error saving activity log: {e}")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/view_data')
def view_data():
    return render_template('upload_data.html', username=current_user.username)

@app.route('/manage_group')
@login_required
def manage_group():
    if current_user.role != 'admin':
        return redirect(request.referrer)

    groups = UserGroup.query.options(db.joinedload(UserGroup.users)).all()

    group_stats = []
    for group in groups:
        users = group.users
        jumlah_akun = len(users)
        user_ids = [u.id for u in users]

        if user_ids:
            total_data = Data.query.filter(Data.user_id.in_(user_ids)).count()
            data_remark_not_1 = Data.query.filter(Data.user_id.in_(user_ids), Data.remark != '1').count()
        else:
            total_data = 0
            data_remark_not_1 = 0

        persen = (data_remark_not_1 / total_data * 100) if total_data > 0 else 0

        group_stats.append({
            'group_id': group.id,
            'company': group.company,
            'logo': group.logo,
            'jumlah_akun': jumlah_akun,
            'total_data': total_data,
            'persen': persen,
        })

    return render_template('manage_group.html',
        username=current_user.username,
        groups=groups,
        group_stats=group_stats,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)


@app.route('/update_group_status', methods=['POST'])
@login_required
def update_group_status():
    group_id = request.form['group_id']
    new_status = request.form['status']

    group = UserGroup.query.get(group_id)
    if group:
        group.status = new_status
        db.session.commit()
        flash('Group status updated successfully', 'success')
    else:
        flash('Group not found', 'danger')

    return redirect(url_for('manage_group'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        input_captcha = request.form.get('captcha_input')
        saved_captcha = session.get('captcha')

        if input_captcha != saved_captcha:
            flash('Kode verifikasi salah!', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user:
            if user.status == 'nonactive':
                flash('Akun sedang disable', 'danger')
                return redirect(url_for('login'))

            group = UserGroup.query.get(user.group)
            if group and group.status == 'nonactive':
                flash('Akun sedang disable', 'danger')
                return redirect(url_for('login'))

            if check_password_hash(user.password, password):
                login_user(user)
                
                if user.role == "user":
                    jakarta_tz = pytz.timezone('Asia/Jakarta')
                    now_jakarta = datetime.now(jakarta_tz)
                    login_log = UserLoginLog(user_id=user.id, login_time=now_jakarta)
                    db.session.add(login_log)
                    db.session.commit()
                
                return redirect(url_for('dashboard'))
            else:
                flash('Username or Password is incorrect!', 'danger')
                return redirect(url_for('login'))

        flash('Username or Password is incorrect!', 'danger')
        return redirect(url_for('login'))

    session['captcha'] = str(random.randint(100000, 999999)) 
    return render_template('login.html', captcha=session['captcha'])

@app.route('/captcha_img')
def captcha_img():
    captcha_text = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    session['captcha'] = captcha_text

    width, height = 160, 60
    image = Image.new('RGB', (width, height), (255, 255, 255))

    font_path = os.path.join(os.path.dirname(__file__), 'static/assets/fonts/arial.ttf')
    font = ImageFont.truetype(font_path, 28)

    draw = ImageDraw.Draw(image)

    for i, char in enumerate(captcha_text):
        draw.text((10 + i * 24, 10), char, font=font, fill=(0, 0, 0))

    for _ in range(5):
        x1, y1 = random.randint(0, width), random.randint(0, height)
        x2, y2 = random.randint(0, width), random.randint(0, height)
        draw.line(((x1, y1), (x2, y2)), fill=(0, 0, 0), width=1)

    image = image.filter(ImageFilter.GaussianBlur(1))

    buffer = io.BytesIO()
    image.save(buffer, 'PNG')
    buffer.seek(0)

    response = make_response(buffer.read())
    response.headers.set('Content-Type', 'image/png')
    return response

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        total_data = Data.query.count()
        data_remarks = Data.query.filter(Data.remark != '1').count()
        total_users = User.query.filter_by(role='user').count()
        total_groups = UserGroup.query.count()
        users = User.query.filter_by(role='user').all()
        remark_labels = {
            "1": "Unremark Case",
            "2": "PTP",
            "3": "Not Active",
            "4": "No Answer",
            "5": "Answer not PTP",
            "6": "Paid",
            "7": "Not PTP"
        }

        user_info = []
        remark_stats = {}
        for u in users:
            total_data_user = Data.query.filter_by(user_id=u.id).count()
            data_remarks_user = Data.query.filter(Data.user_id == u.id).all()

            for dr in data_remarks_user:
                label = remark_labels.get(str(dr.remark), f"Unknown ({dr.remark})")
                remark_stats[label] = remark_stats.get(label, 0) + 1

            remarks_count_user = len(data_remarks_user)
            last_exp = (
                db.session.query(Data.exp_date)
                .filter_by(user_id=u.id)
                .order_by(Data.exp_date.desc())
                .first()
            )

            user_info.append({
                "name": u.username,
                "group": u.group_rel.company if u.group_rel else "-",
                "total_data": total_data_user,
                "remarks_data": remarks_count_user,
                "exp_date": last_exp[0].strftime("%Y-%m-%d") if last_exp and last_exp[0] else "-"
            })

        donut_data = [[label, count] for label, count in remark_stats.items()]

        return render_template(
            'dashboard_admin.html',
            username=current_user.username,
            num_sip=current_user.num_sip,
            pas_sip=current_user.pas_sip,
            user_info=user_info,
            donut_data=donut_data,
            total_data=total_data,
            data_remarks=data_remarks,
            total_users=total_users,
            total_groups=total_groups
        )

    elif current_user.role == 'user':
        total_data = Data.query.filter_by(user_id=current_user.id).count()
        data_remarks = Data.query.filter(Data.user_id == current_user.id, Data.remark != '1').count()
        remark_percentage = round((data_remarks / total_data) * 100, 2) if total_data else 0

        remark_labels = {
            "1": "Unremark Case",
            "2": "PTP",
            "3": "Not Active",
            "4": "No Answer",
            "5": "Answer not PTP",
            "6": "Paid",
            "7": "Not PTP"
        }

        remark_counts = {}
        for code in remark_labels.keys():
            count = Data.query.filter(
                Data.user_id == current_user.id,
                Data.remark == code
            ).count()
            remark_counts[code] = count

        remark_order = ["1", "7", "2", "3", "4", "5", "6"]

        remarks_list = []
        for code in remark_order:
            count = remark_counts.get(code, 0)
            percent = round((count / total_data) * 100, 2) if total_data else 0
            remarks_list.append({
                "label": remark_labels[code],
                "count": count,
                "percent": percent
            })

        return render_template(
            'dashboard_user.html',
            username=current_user.username,
            num_sip=current_user.num_sip,
            pas_sip=current_user.pas_sip,
            total_data=total_data,
            data_remarks=data_remarks,
            remark_percentage=remark_percentage,
            remarks_list=remarks_list
    )
    else:
        return redirect(url_for('login'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/add_group', methods=['POST'])
@login_required
def add_group():
    try:
        company = request.form['company']
        overdue = request.form['overdue']

        logo_paths = {
            "Uatas": "/static/assets/img/3rd/uatas.png",
            "Akulaku": "/static/assets/img/3rd/akulaku.png",
            "Beaute": "/static/assets/img/3rd/danarupiah.jpeg",
            "Debito": "/static/assets/img/3rd/debito.jpeg",
            "Finplus": "/static/assets/img/3rd/finplus.jpeg",
            "Julo": "/static/assets/img/3rd/julo.png",
            "Kredivo": "/static/assets/img/3rd/kredivo.jpg",
            "PinjamYuk": "/static/assets/img/3rd/pinjamyuk.jpg",
            "TIN": "/static/assets/img/3rd/tin.png",
            "TrustIQ": "/static/assets/img/3rd/trustiq.png",
            "Twinkle": "/static/assets/img/3rd/twinkle.png",
            "UangMe": "/static/assets/img/3rd/uangme.png",
            "BankVima": "/static/assets/img/3rd/vima.jpg",
            "Oppo": "/static/assets/img/3rd/oppo.png",
            "DanaRupiah": "/static/assets/img/3rd/danarupiah.jpeg"
        }

        logo = logo_paths.get(company, "")

        new_group = UserGroup(company=company, overdue=overdue, logo=logo)  
        db.session.add(new_group)
        db.session.commit()

        flash("Group added successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error: {str(e)}", "danger")

    return redirect(url_for('manage_group'))

@app.route('/add-account', methods=['POST'])
def add_account():
    id_system = request.form['id']
    username = request.form['username']
    password = request.form['password']
    phone = request.form['number']
    email = request.form['email']
    group_id = request.form['group']
    role = request.form['role']

    hashed_password = generate_password_hash(password)

    if role == 'admin':
        id_system = None
        phone = None
        email = None
        group_id = None 
        num_sip = None
        pas_sip = None
    else:
        num_sip = request.form.get('num_sip', None)  
        pas_sip = request.form.get('pas_sip', None)  

        if not group_id:
            flash('Group harus dipilih untuk user biasa.', 'error')
            return redirect(url_for('manage_users'))

    new_user = User(
        id_system=id_system, 
        username=username,
        password=hashed_password,
        phone=phone,  
        email=email,  
        group=group_id, 
        role=role,
        status='active',
        num_sip=num_sip,  
        pas_sip=pas_sip   
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        flash('Akun berhasil ditambahkan.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menambahkan akun: {e}', 'error')

    return redirect(url_for('manage_users'))

@app.route('/manage-users', methods=['GET'])
def manage_users():
    page = request.args.get('page', 1, type=int)
    per_page = 10

    if current_user.role != 'admin':
        return redirect(request.referrer)

    users_paginate = User.query.filter_by(role='user').paginate(page=page, per_page=per_page, error_out=False)
    groups = UserGroup.query.all()

    for user in users_paginate.items:
        group = UserGroup.query.filter_by(id=user.group).first()
        if group and group.status == 'nonactive':
            user.status = 'nonactive'

        user.total_data = Data.query.filter_by(user_id=user.id).count()

        user.total_remarks = Data.query.filter(Data.user_id == user.id, Data.remark != '1').count()

        exp_data = Data.query.filter_by(user_id=user.id).first()
        user.exp_date_display = exp_data.exp_date.strftime("%d-%m-%Y") if exp_data and exp_data.exp_date else "-"

    return render_template(
        'manage_account.html',
        users=users_paginate.items, 
        groups=groups,
        next_url=users_paginate.next_num,
        prev_url=users_paginate.prev_num,
        has_next=users_paginate.has_next,
        has_prev=users_paginate.has_prev,
        pages=users_paginate.pages,
        current_page=page,
        username=current_user.username,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/user/<int:user_id>', methods=['GET'])
@login_required
def user_details(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)

    remark_mapping = {
        '1': 'Not PTP',
        '2': 'PTP',
        '3': 'Not Active',
        '4': 'No Answer',
        '5': 'Answer Not PTP',
        '6': 'Paid'
    }

    total_per_remark = {}
    for key, label in remark_mapping.items():
        total_per_remark[label] = Data.query.filter_by(user_id=user.id, remark=key).count()

    total_data = Data.query.filter_by(user_id=user.id).count()

    total_remarks_count = Data.query.filter(Data.user_id == user.id, Data.remark != '1').count()
    remarks_percentage = round((total_remarks_count / total_data * 100), 2) if total_data > 0 else 0

    user_status = user.status

    exp_data = Data.query.filter_by(user_id=user.id).first()
    exp_date_display = exp_data.exp_date.strftime("%d-%m-%Y") if exp_data and exp_data.exp_date else "-"

    last_logins = (
        UserLoginLog.query
        .filter_by(user_id=user.id)
        .order_by(UserLoginLog.login_time.desc())
        .limit(5)
        .all()
    )

    return render_template(
        'user_details.html',
        user=user,
        total_per_remark=total_per_remark,
        total_data=total_data,
        total_remarks_count=total_remarks_count,
        remarks_percentage=remarks_percentage,
        user_status=user_status,
        exp_date_display=exp_date_display,
        last_logins=last_logins
    )

@app.route('/delete-group', methods=['POST'])
@login_required
def delete_group():
    group_id = request.form['group']
    delete_option = request.form['delete']  

    try:
        group = UserGroup.query.get(group_id)

        if group:
            if delete_option == 'temp':
                group.status = 'nonactive'
                db.session.commit()
                flash('Group status updated to nonactive.', 'success')

            elif delete_option == 'perm':
                users_to_delete = User.query.filter_by(group=group.id).all()
                for user in users_to_delete:
                    db.session.delete(user)  

                db.session.delete(group) 
                db.session.commit()
                flash('Group and associated users deleted permanently.', 'success')
        else:
            flash('Group not found.', 'danger')

    except Exception as e:
        db.session.rollback()
        flash(f'Error: {str(e)}', 'danger')

    return redirect(url_for('manage_group'))

@app.route('/delete-account', methods=['POST'])
def delete_account():
    user_id = request.form['user_id']
    delete_type = request.form['delete_type']

    user = User.query.get(user_id)
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('manage_users'))

    if delete_type == 'temp':
        user.status = 'nonactive'
        db.session.commit()
        flash('User temporarily disconnected.', 'warning')
    elif delete_type == 'perm':
        db.session.delete(user)
        db.session.commit()
        flash('User permanently deleted.', 'danger')

    return redirect(url_for('manage_users'))

@app.route('/update_user', methods=['POST'])
@login_required
def update_user():
    user_id = request.form['user_id']
    new_status = request.form['status']
    new_password = request.form['password']

    user = User.query.get(user_id)
    if user:
        user.status = new_status
        if new_password.strip():
            user.password = generate_password_hash(new_password)
        db.session.commit()
        flash('User updated successfully.', 'success')
    else:
        flash('User not found.', 'danger')

    return redirect(url_for('manage_users'))

@app.route('/upload_data', methods=['GET', 'POST'])
@login_required
def upload_data():
    if current_user.role != 'admin':
        return redirect(request.referrer)

    if request.method == 'POST':
        file = request.files.get('file')
        user_id = request.form.get('user_id')
        exp_date = request.form.get('date')

        if not file or file.filename == '':
            flash('File tidak ditemukan.', 'danger')
            return redirect(url_for('upload_data'))

        if not user_id or not exp_date:
            flash('User dan tanggal exp harus diisi.', 'danger')
            return redirect(url_for('upload_data'))

        try:
            df = pd.read_excel(file)

            required_columns = [
                'Order Number', 'Nama Nasabah', 'No HP', 'Alamat', 'Pekerjaan',
                'Total Tagihan', 'Overdue', 
                'Nama Emergency Contact 1', 'Nomor Emergency Contact 1',
                'Nama Emergency Contact 2', 'Nomor Emergency Contact 2'
            ]

            if not all(col in df.columns for col in required_columns):
                flash('Format kolom Excel tidak sesuai.', 'danger')
                return redirect(url_for('upload_data'))

            if df[required_columns].isnull().any().any():
                flash('Kolom yang diupload tidak lengkap.', 'danger')
                return redirect(url_for('upload_data'))

            for _, row in df.iterrows():
                waktu_peminjaman = row.get('Waktu Peminjaman')
                pokok_pinjaman = row.get('Pokok Pinjaman', 0)
                optional_1 = row.get('Optional 1')
                optional_2 = row.get('Optional 2')
                optional_3 = row.get('Optional 3')
                optional_4 = row.get('Optional 4')

                if pd.isna(waktu_peminjaman):
                    waktu_peminjaman = None
                if pd.isna(pokok_pinjaman):
                    pokok_pinjaman = None 
                if pd.isna(optional_1):
                    optional_1 = None 
                if pd.isna(optional_2):
                    optional_2 = None 
                if pd.isna(optional_3):
                    optional_3 = None 
                if pd.isna(optional_4):
                    optional_4 = None

                data = Data(
                    order_no=row['Order Number'],
                    nama_nasabah=row['Nama Nasabah'],
                    phone=row['No HP'],
                    alamat=row['Alamat'],
                    pekerjaan=row['Pekerjaan'], 
                    total_tagihan=row['Total Tagihan'],
                    overdue=row['Overdue'],
                    nama_ec1=row['Nama Emergency Contact 1'],
                    nomor_ec1=row['Nomor Emergency Contact 1'],
                    nama_ec2=row['Nama Emergency Contact 2'],
                    phone_ec2=row['Nomor Emergency Contact 2'],
                    exp_date=exp_date,
                    tanggal_upload=datetime.now(),
                    user_id=user_id,
                    remark='1',
                    catatan='',
                    optional_1=optional_1,
                    optional_2=optional_2,
                    optional_3=optional_3,
                    optional_4=optional_4
                )
                db.session.add(data)

            db.session.commit()
            flash('Data berhasil diupload.', 'success')

        except Exception as e:
            db.session.rollback()
            flash(f'Terjadi kesalahan: {e}', 'danger')

        return redirect(url_for('upload_data'))
    
    user_data_summary = (
        db.session.query(
            User.id.label('user_id'),
            User.id_system,
            User.username,
            func.count(Data.id).label('total_data'),
            func.max(Data.tanggal_upload).label('tanggal_upload'),
            UserGroup.company.label('group_name'),
            UserGroup.logo.label('group_logo'),
            User.status,
            func.max(Data.exp_date).label('exp_date')
        )
        .join(Data, Data.user_id == User.id)
        .join(UserGroup, User.group == UserGroup.id)
        .filter(User.status == 'active', User.role == 'user')
        .group_by(User.id, User.id_system, User.username, UserGroup.company, UserGroup.logo, User.status)
        .all()
    )

    all_users = User.query.filter_by(role='user', status='active').all()

    threshold = datetime.utcnow() - timedelta(minutes=5)
    online_status = case(
        (User.last_seen >= threshold, 1),
        else_=0
    )

    sidebar_users = User.query.filter_by(role='user', status='active')\
        .order_by(desc(online_status), desc(User.last_seen))\
        .all()

    return render_template(
        'manage_data.html',
        users=user_data_summary,
        all_users=all_users,
        sidebar_users=sidebar_users,
        username=current_user.username,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/login_logs')
@login_required
def login_logs():
    if current_user.role != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('dashboard'))

    logs = UserLoginLog.query.order_by(UserLoginLog.login_time.desc()).all()
    users = User.query.all()

    return render_template('log.html', logs=logs, users=users)

@app.route('/upload_data/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_data_user(user_id):
    if current_user.role != 'admin':
        flash('Akses ditolak.', 'danger')
        return redirect(url_for('upload_data'))

    try:
        Data.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        flash('Data berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Gagal menghapus data: {e}', 'danger')

    return redirect(url_for('upload_data'))

@app.route('/delete')
def delete():
    page = request.args.get('page', 1, type=int)
    per_page = 10  

    if current_user.role != 'admin':
        return redirect(request.referrer)
    
    user_data_summary = (
        db.session.query(
            User.id_system,
            User.username,
            func.count(Data.id).label('total_data'),
            func.max(Data.tanggal_upload).label('tanggal_upload'),
            UserGroup.company.label('group_name')
        )
        .join(Data, Data.user_id == User.id)
        .join(UserGroup, User.group == UserGroup.id)
        .group_by(User.id_system, User.username, UserGroup.company)
        .paginate(page=page, per_page=per_page, error_out=False) 
    )

    user_data_summary_items = user_data_summary.items  
    total_pages = user_data_summary.pages    
    current_page = user_data_summary.page  

    return render_template(
        'manage_data.html',
        username=current_user.username,
        user_data_summary=user_data_summary_items,
        total_pages=total_pages,
        current_page=current_page,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/delete/<string:id_system>', methods=['POST'])
@login_required
def delete_user_data(id_system):
    try:
        user = User.query.filter_by(id_system=id_system).first()
        if not user:
            flash('User tidak ditemukan.', 'danger')
            return redirect(url_for('delete'))

        data_to_delete = Data.query.filter_by(user_id=user.id).all()
        for data in data_to_delete:
            db.session.delete(data)

        db.session.commit()
        flash('Data berhasil dihapus.', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Terjadi kesalahan: {e}', 'danger')

    return redirect(url_for('delete'))

from sqlalchemy import cast, Integer

def mask_phone(phone):
    if not phone or len(phone) < 6:
        return phone
    return phone[:4] + "****" + phone[-4:]

app.jinja_env.filters['mask_phone'] = mask_phone

@app.route('/my-case')
@login_required
def my_case():
    query = Data.query.options(
        joinedload(Data.user).joinedload(User.group_rel)
    )

    if current_user.role != 'admin':
        flash("Access denied. Only admin can perform this action.", "danger")
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    remark_filter = request.args.get('remark')
    if remark_filter:
        query = query.filter(Data.remark == remark_filter)

    outstanding_min = request.args.get('outstanding_min')
    outstanding_max = request.args.get('outstanding_max')

    if outstanding_min:
        try:
            outstanding_min = int(outstanding_min)
            query = query.filter(
                cast(Data.total_tagihan, Integer) >= outstanding_min
            )
        except ValueError:
            pass

    if outstanding_max:
        try:
            outstanding_max = int(outstanding_max)
            query = query.filter(
                cast(Data.total_tagihan, Integer) <= outstanding_max
            )
        except ValueError:
            pass

    staff_id = request.args.get('staff')
    if staff_id:
        query = query.filter(Data.user_id == int(staff_id))

    query_result = query.all()

    remarks_map = {
        '1': 'Unremark Case',
        '7': 'Not PTP',
        '2': 'PTP',
        '3': 'Not Active',
        '4': 'No Answer',
        '5': 'Answer not PTP',
        '6': 'Paid'
    }

    for d in query_result:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        d.remarks_display = remarks_map.get(str(d.remark), 'Unknown')

    users_list = User.query.filter_by(role="User").all()

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    remark_filter = request.args.get('remark')
    outstanding_min = request.args.get('outstanding_min')
    outstanding_max = request.args.get('outstanding_max')
    staff_id = request.args.get('staff')

    return render_template(
        'manage_case.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=query_result,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip,
        users_list=users_list,
        staff_id=staff_id,
        remark_filter=remark_filter,
        outstanding_min=outstanding_min,
        outstanding_max=outstanding_max
        )

@app.route('/my-case/<int:data_id>')
@login_required
def my_case_detail(data_id):
    data = Data.query.get_or_404(data_id)

    remarks_map = {
        '1': 'Unremark Case',
        '7': 'Not PTP',
        '2': 'PTP',
        '3': 'Not Active',
        '4': 'No Answer',
        '5': 'Answer not PTP',
        '6': 'Paid'
    }
    data.remarks_display = remarks_map.get(str(data.remark), 'Unknown')

    try:
        data.pokok_pinjaman_int = int(data.pokok_pinjaman.replace('.', '').replace(',', '').strip())
    except:
        data.pokok_pinjaman_int = 0
    try:
        data.total_tagihan_int = int(data.total_tagihan.replace('.', '').replace(',', '').strip())
    except:
        data.total_tagihan_int = 0
    try:
        data.overdue = int(data.overdue)
    except:
        data.overdue = 0

    user = data.user
    group = user.group_rel if user else None

    return render_template(
        'detail_case.html',
        data=data,
        user=user,
        group=group
    )

@app.route('/ptp')
@login_required
def ptp():
    query = Data.query.filter(Data.remark == '2')

    if current_user.role != 'admin':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    sort_customer = request.args.get('customer_name')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'ptp.html',
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/admin/not-active')
@login_required
def not_active_admin():
    query = Data.query.filter(Data.remark == '3')

    if current_user.role != 'admin':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    sort_customer = request.args.get('customer_name')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'not_active.html',
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/admin/no-answer')
@login_required
def no_answer_admin():
    query = Data.query.filter(Data.remark == '4')

    if current_user.role != 'admin':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    sort_customer = request.args.get('customer_name')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'no_answer.html',
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/admin/answer-not-ptp')
@login_required
def answer_not_ptp_admin():
    query = Data.query.filter(Data.remark == '5')

    if current_user.role != 'admin':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    sort_customer = request.args.get('customer_name')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'answer_not_ptp.html',
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/admin/paid')
@login_required
def paid_admin():
    query = Data.query.filter(Data.remark == '6')

    if current_user.role != 'admin':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    sort_customer = request.args.get('customer_name')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'lunas.html',
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/detail_data/<int:id>')
@login_required
def detail_data(id):
    data = Data.query.get_or_404(id)

    def format_rupiah(nominal):
        return f"Rp {nominal:,.0f}".replace(",", ".")

    try:
        data.pokok_pinjaman_int = int(data.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        data.pokok_pinjaman_rp = format_rupiah(data.pokok_pinjaman_int)
    except:
        data.pokok_pinjaman_int = 0
        data.pokok_pinjaman_rp = "Rp0"

    try:
        data.total_tagihan_int = int(data.total_tagihan.replace('.', '').replace(',', '').strip())
        data.total_tagihan_rp = format_rupiah(data.total_tagihan_int)
    except:
        data.total_tagihan_int = 0
        data.total_tagihan_rp = "Rp0"

    return render_template('detail_data.html', data=data, username=current_user.username)

@app.route('/my-data')
@login_required
def my_data():
    query = Data.query.join(User).join(UserGroup, User.group == UserGroup.id).filter(
        Data.user_id == current_user.id,
        Data.remark == "7"
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    sort_customer = request.args.get('customer_name')
    sort_principal = request.args.get('principal')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_principal == '1':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int, reverse=True)
    elif sort_principal == '2':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 3:
            page_numbers = [1, 2, 3, 4, "...", total_pages]
        elif page >= total_pages - 2:
            page_numbers = [1, "...", total_pages-3, total_pages-2, total_pages-1, total_pages]
        else:
            page_numbers = [1, "...", page-1, page, page+1, "...", total_pages]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_not_ptp.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers, 
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/no-remarks')
@login_required
def no_remarks():
    query = Data.query.join(User).join(UserGroup, User.group == UserGroup.id).filter(
        Data.user_id == current_user.id,
        Data.remark == "1"
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    sort_customer = request.args.get('customer_name')
    sort_principal = request.args.get('principal')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_principal == '1':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int, reverse=True)
    elif sort_principal == '2':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = query_result[start:end]
    total_pages = (total + per_page - 1) // per_page

    pages_to_show = []
    if total_pages > 1:
        pages_to_show.append(1)
        if page - 1 > 2:
            pages_to_show.append("...")
        for p in range(page - 1, page + 2):
            if 1 < p < total_pages: 
                pages_to_show.append(p)
        if page + 1 < total_pages - 1:
            pages_to_show.append("...")
        if total_pages not in pages_to_show:
            pages_to_show.append(total_pages) 

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_no_remark.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        query_params=query_params,
        pages_to_show=pages_to_show,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/lunas')
@login_required
def lunas():
    query = Data.query.filter(
        Data.remark == '6',
        Data.user_id == current_user.id
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    sort_customer = request.args.get('customer_name')
    sort_principal = request.args.get('principal')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_principal == '1':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int, reverse=True)
    elif sort_principal == '2':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 3:
            page_numbers = [1, 2, 3, 4, "...", total_pages]
        elif page >= total_pages - 2:
            page_numbers = [1, "...", total_pages-3, total_pages-2, total_pages-1, total_pages]
        else:
            page_numbers = [1, "...", page-1, page, page+1, "...", total_pages]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_paid.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/user-stats')
@login_required
def user_stats():
    if current_user.role != 'admin':
        return redirect(request.referrer)

    page = request.args.get('page', 1, type=int)
    per_page = 10

    keyword = request.args.get('keyword', '').strip()
    sort_option = request.args.get('outstanding') 

    total_users = User.query.filter_by(role='user').count()

    total_data = db.session.query(func.count(Data.id)).scalar() or 0
    total_data_selain_1 = db.session.query(func.count(Data.id)).filter(Data.remark != '1').scalar() or 0
    
    persen_selain_1 = 0
    if total_data > 0:
        persen_selain_1 = round((total_data_selain_1 / total_data) * 100, 2)  

    groups_info = (
        db.session.query(
            UserGroup.company.label('group'),
            UserGroup.status,
            UserGroup.overdue,
            func.count(User.id).label('jumlah_user')
        )
        .outerjoin(User, User.group == UserGroup.id)
        .filter(User.role == 'user')
        .group_by(UserGroup.id)
        .all()
    )

    base_query = db.session.query(
        User.id_system,
        User.id,
        User.username,
        User.email,
        func.count(Data.id).label('total_data'),
        func.count(case((Data.remark == '1', 1))).label('remark_1_count'),
        UserGroup.company.label('company'),
        User.status
    ).outerjoin(Data, User.id == Data.user_id
    ).outerjoin(UserGroup, User.group == UserGroup.id
    ).filter(User.role == 'user')

    if keyword:
        base_query = base_query.filter(
            (User.id_system.ilike(f"%{keyword}%")) |
            (User.username.ilike(f"%{keyword}%"))
        )

    grouped_query = base_query.group_by(User.id).subquery()

    if sort_option == '1':  
        final_query = db.session.query(grouped_query).order_by(desc(grouped_query.c.total_data))
    elif sort_option == '2':  
        final_query = db.session.query(grouped_query).order_by(asc(grouped_query.c.total_data))
    else:
        final_query = db.session.query(grouped_query)

    total_rows = db.session.query(func.count()).select_from(grouped_query).scalar()
    total_pages = (total_rows + per_page - 1) // per_page
    paginated_users = final_query.offset((page - 1) * per_page).limit(per_page).all()

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    remark_counts = {}
    for i in range(1, 7):
        remark_counts[i] = Data.query.filter_by(remark=str(i)).count()

    return render_template('user_stats.html',
                           users=paginated_users,
                           groups_info=groups_info,
                           current_page=page,
                           total_pages=total_pages,
                           query_params=query_params,
                           keyword=keyword,
                           sort_option=sort_option,
                           total_users=total_users,
                           total_data_selain_1=total_data_selain_1,
                           total_data=total_data,
                           persen_selain_1=persen_selain_1, 
                           remark_counts=remark_counts)

from sqlalchemy import func, case

@app.route('/user/<int:user_id>')
@login_required
def user_detail(user_id):
    if current_user.role != 'admin':
        return redirect(request.referrer)

    user = User.query.get_or_404(user_id)

    remarks_mapping = {
        '1': 'Unremark Case',
        '7': 'Not PTP',
        '2': 'PTP',
        '3': 'Not Active',
        '4': 'No Answer',
        '5': 'Answer not PTP',
        '6': 'Paid'
    }

    total_data = Data.query.filter_by(user_id=user.id).count()

    remarks_stats = dict(
        db.session.query(Data.remark, func.count(Data.id))
        .filter_by(user_id=user.id)
        .group_by(Data.remark)
        .all()
    )

    remarks_list = []
    for i in range(1, 7):
        remark_key = str(i)
        count = remarks_stats.get(remark_key, 0)
        try:
            percent = round((count / total_data) * 100, 2)
        except ZeroDivisionError:
            percent = 0
        remarks_list.append({
            "remark": remark_key,
            "label": remarks_mapping[remark_key],
            "count": count,
            "percent": percent
        })

    return render_template(
        'user_detail.html',
        user=user,
        total_data=total_data,
        remarks_list=remarks_list
    )

@app.route('/not-active')
@login_required
def not_active():
    query = Data.query.filter(
        Data.remark == '3',
        Data.user_id == current_user.id
    )
    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    sort_customer = request.args.get('customer_name')
    sort_principal = request.args.get('principal')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_principal == '1':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int, reverse=True)
    elif sort_principal == '2':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = query_result[start:end]
    total_pages = (total + per_page - 1) // per_page

    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 3:
            page_numbers = [1, 2, 3, 4, "...", total_pages]
        elif page >= total_pages - 2:
            page_numbers = [1, "...", total_pages-3, total_pages-2, total_pages-1, total_pages]
        else:
            page_numbers = [1, "...", page-1, page, page+1, "...", total_pages]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_not_active.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/no-answer')
@login_required
def no_answer():
    query = Data.query.filter(
        Data.remark == '4',
        Data.user_id == current_user.id
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    sort_customer = request.args.get('customer_name')
    sort_principal = request.args.get('principal')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_principal == '1':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int, reverse=True)
    elif sort_principal == '2':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 3:
            page_numbers = [1, 2, 3, 4, "...", total_pages]
        elif page >= total_pages - 2:
            page_numbers = [1, "...", total_pages-3, total_pages-2, total_pages-1, total_pages]
        else:
            page_numbers = [1, "...", page-1, page, page+1, "...", total_pages]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_no_answer.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/answer-no-ptp')
@login_required
def answer_no_ptp():
    query = Data.query.filter(
        Data.remark == '5',
        Data.user_id == current_user.id
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)

    query_result = []
    for d in query:
        try:
            d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        except:
            d.pokok_pinjaman_int = 0
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0
        try:
            d.overdue = int(d.overdue)
        except:
            d.overdue = 0

        if (
            (min_principal is None or d.pokok_pinjaman_int >= min_principal) and
            (max_principal is None or d.pokok_pinjaman_int <= max_principal) and
            (min_overdue is None or d.overdue >= min_overdue) and
            (max_overdue is None or d.overdue <= max_overdue)
        ):
            query_result.append(d)

    sort_customer = request.args.get('customer_name')
    sort_principal = request.args.get('principal')
    sort_outstanding = request.args.get('outstanding')

    if sort_customer == '1':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower())
    elif sort_customer == '2':  
        query_result.sort(key=lambda x: x.nama_nasabah.lower(), reverse=True)

    if sort_principal == '1':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int, reverse=True)
    elif sort_principal == '2':  
        query_result.sort(key=lambda x: x.pokok_pinjaman_int)

    if sort_outstanding == '1':  
        query_result.sort(key=lambda x: x.total_tagihan_int, reverse=True)
    elif sort_outstanding == '2':  
        query_result.sort(key=lambda x: x.total_tagihan_int)

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 3:
            page_numbers = [1, 2, 3, 4, "...", total_pages]
        elif page >= total_pages - 2:
            page_numbers = [1, "...", total_pages-3, total_pages-2, total_pages-1, total_pages]
        else:
            page_numbers = [1, "...", page-1, page, page+1, "...", total_pages]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_answer_not_ptp.html',
        username=current_user.username,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        data_list=paginated_data,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )


@app.route('/call')
@login_required
def call():
    nomor = request.args.get('nomor')
    if not nomor:
        return "Nomor tidak ditemukan.", 400
    return render_template(
        'call.html',
        nomor=nomor,
        sip_server="ld.infin8link.com:7060",
        domain="ld.infin8link.com:7060",
        username=current_user.num_sip,
        password=current_user.pas_sip
    )

@app.route('/user-ptp')
@login_required
def user_ptp():
    query = Data.query.filter(
        Data.remark == '2',
        Data.user_id == current_user.id
    )

    if current_user.role != 'user':
        return redirect(request.referrer)

    keyword = request.args.get('keyword')
    if keyword:
        query = query.filter(
            or_(
                Data.order_no.ilike(f"%{keyword}%"),
                Data.nama_nasabah.ilike(f"%{keyword}%"),
                Data.phone.ilike(f"%{keyword}%")
            )
        )

    min_principal = request.args.get('min_principal', type=int)
    max_principal = request.args.get('max_principal', type=int)
    if min_principal is not None or max_principal is not None:
        all_data = query.all()
        filtered_data = []
        for d in all_data:
            try:
                pokok = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
                if (
                    (min_principal is None or pokok >= min_principal) and
                    (max_principal is None or pokok <= max_principal)
                ):
                    d.pokok_pinjaman_int = pokok
                    filtered_data.append(d)
            except:
                continue
        query_result = filtered_data
    else:
        query_result = query.all()
        for d in query_result:
            try:
                d.pokok_pinjaman_int = int(d.pokok_pinjaman.replace('.', '').replace(',', '').strip())
            except:
                d.pokok_pinjaman_int = 0

    min_overdue = request.args.get('min_overdue', type=int)
    max_overdue = request.args.get('max_overdue', type=int)
    if min_overdue is not None or max_overdue is not None:
        temp = []
        for d in query_result:
            try:
                ovd = int(d.overdue)
                if (
                    (min_overdue is None or ovd >= min_overdue) and
                    (max_overdue is None or ovd <= max_overdue)
                ):
                    d.overdue = ovd
                    temp.append(d)
            except:
                continue
        query_result = temp

    for d in query_result:
        try:
            d.total_tagihan_int = int(d.total_tagihan.replace('.', '').replace(',', '').strip())
        except:
            d.total_tagihan_int = 0

    page = request.args.get('page', 1, type=int)
    per_page = 10
    total = len(query_result)
    total_pages = (total + per_page - 1) // per_page
    paginated_data = query_result[(page - 1) * per_page: page * per_page]

    if total_pages <= 7:
        page_numbers = list(range(1, total_pages + 1))
    else:
        if page <= 3:
            page_numbers = [1, 2, 3, 4, "...", total_pages]
        elif page >= total_pages - 2:
            page_numbers = [1, "...", total_pages-3, total_pages-2, total_pages-1, total_pages]
        else:
            page_numbers = [1, "...", page-1, page, page+1, "...", total_pages]

    query_params = request.args.to_dict()
    query_params.pop('page', None)

    group_obj = UserGroup.query.filter_by(id=current_user.group).first()
    group_name = group_obj.company if group_obj else 'N/A'

    return render_template(
        'user_manage_ptp.html',  
        username=current_user.username,
        data_list=paginated_data,
        group=current_user.group,
        group_name=group_name,
        id_system=current_user.id_system,
        current_page=page,
        total_pages=total_pages,
        page_numbers=page_numbers,
        query_params=query_params,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip
    )

@app.route('/user_detail_data/<int:id>')
@login_required
def user_detail_data(id):
    data = Data.query.get_or_404(id)

    if current_user.role != 'user':
        return redirect(request.referrer)

    def format_rupiah(nominal):
        return f"Rp {nominal:,.0f}".replace(",", ".")

    try:
        data.pokok_pinjaman_int = int(data.pokok_pinjaman.replace('.', '').replace(',', '').strip())
        data.pokok_pinjaman_rp = format_rupiah(data.pokok_pinjaman_int)
    except:
        data.pokok_pinjaman_int = 0
        data.pokok_pinjaman_rp = "Rp0"

    try:
        data.total_tagihan_int = int(data.total_tagihan.replace('.', '').replace(',', '').strip())
        data.total_tagihan_rp = format_rupiah(data.total_tagihan_int)
    except:
        data.total_tagihan_int = 0
        data.total_tagihan_rp = "Rp0"

    return render_template('user_manage_detail.html', 
        data=data, 
        username=current_user.username,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip)

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404

@app.route('/ganti-sip', methods=['POST'])
@login_required
def ganti_sip():
    try:
        current_user.num_sip = request.form['num_sip']
        current_user.pas_sip = request.form['pas_sip']
        db.session.commit()
        flash("Nomor SIP berhasil diperbarui.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Terjadi kesalahan: {str(e)}", "danger")
    
    return redirect(request.referrer or url_for('dashboard'))

@app.route('/submit-call', methods=['POST'])
@login_required
def submit_call():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    data = Data.query.filter_by(id=data_id, user_id=current_user.id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(request.referrer or url_for('my_data'))

    data.remark = remark
    if note is not None:
        data.catatan = note
    db.session.commit()

    flash('Data berhasil diperbarui.', 'success')
    return redirect(request.referrer or url_for('my_data'))

@app.route('/admin-submit-call', methods=['POST'])
@login_required
def admin_submit_call():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    data = Data.query.filter_by(id=data_id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('my_case'))

    data.remark = remark
    if note is not None:
        data.catatan = note
    db.session.commit()

    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('my_case'))

@app.route('/submit-call-ptp', methods=['POST'])
@login_required
def submit_call_ptp():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    data = Data.query.filter_by(id=data_id, user_id=current_user.id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('user_ptp'))

    data.remark = remark
    if note is not None:
        data.catatan = note

    db.session.commit()
    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('user_ptp'))

@app.route('/admin-submit-call-ptp', methods=['POST'])
@login_required
def admin_submit_call_ptp():
    data_id = request.form.get('data_id')
    remark = request.form.get('remark')
    note = request.form.get('note')

    print(f"Data ID: {data_id}, Remark: {remark}, Note: {note}")

    data = Data.query.filter_by(id=data_id).first()
    if not data:
        flash('Data tidak ditemukan atau tidak sesuai.', 'error')
        return redirect(url_for('ptp'))

    data.remark = remark
    if note is not None:
        data.catatan = note

    db.session.commit()
    flash('Data berhasil diperbarui.', 'success')
    return redirect(url_for('ptp'))

@app.route('/log_user')
@login_required
def log_user():
    if current_user.role != 'admin':
        return redirect(request.referrer)
    
    if current_user.role == 'admin':
        page = request.args.get('page', 1, type=int)  
        per_page = 10

        activities = UserActivity.query.order_by(UserActivity.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)

        return render_template('log_user.html',
        activities=activities.items, 
        username=current_user.username,
        num_sip=current_user.num_sip,
        pas_sip=current_user.pas_sip,
        pagination=activities)  
    
    else:
        return redirect(url_for('home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5009, host='0.0.0.0')  