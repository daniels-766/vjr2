from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from extensions import db

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
