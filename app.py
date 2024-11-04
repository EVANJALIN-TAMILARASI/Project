from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///leave_management.db'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

migrate = Migrate(app, db)


# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(50))  # "employee" or "manager"


class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    start_date = db.Column(db.String(50))
    end_date = db.Column(db.String(50))
    reason = db.Column(db.String(200))
    status = db.Column(db.String(50), default="Pending")  # Pending, Approved, Rejected
    user = db.relationship('User', backref='leave_requests')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access Denied: Admins Only')
        return redirect(url_for('dashboard'))
    
    users = User.query.all()  # List all users
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if current_user.role != 'admin':
        flash('Access Denied: Admins Only')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')  # Select either "employee" or "manager"
        
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already exists.')
            return redirect(url_for('create_user'))

        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_user.html')

@app.route('/admin/update_role/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_role(user_id):
    if current_user.role != 'admin':
        flash('Access Denied: Admins Only')
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    if request.method == 'POST':
        role = request.form.get('role')  # Update role to "employee" or "manager"
        user.role = role
        db.session.commit()
        flash('User role updated successfully!')
        return redirect(url_for('admin_dashboard'))

    return render_template('update_role.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        flash('Access Denied: Admins Only')
        return redirect(url_for('dashboard'))

    user = User.query.get(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!')
    return redirect(url_for('admin_dashboard'))






@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        


        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash('Email already exists. Please log in.')
            return redirect(url_for('login'))

        new_user = User(name=name, email=email, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! You can log in now.')
        return redirect(url_for('login'))
    return render_template('signup.html',signup = signup)

   


@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        return redirect(url_for('login'))
    return render_template('login.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and user.password == password:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials, please try again.')
    return render_template('login.html')


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'manager':
        leave_requests = LeaveRequest.query.filter_by(status='Pending').all()
        return render_template('manage_leaves.html', leave_requests=leave_requests)
    else:
        leave_requests = LeaveRequest.query.filter_by(user_id=current_user.id).all()
        return render_template('dashboard.html', leave_requests=leave_requests)
    


@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    if request.method == 'POST':
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        reason = request.form.get('reason')
        leave_request = LeaveRequest(user_id=current_user.id, start_date=start_date, end_date=end_date, reason=reason)
        db.session.add(leave_request)
        db.session.commit()
        flash('Leave request submitted!')
        return redirect(url_for('dashboard'))
    return render_template('leave_request.html')


@app.route('/approve_leave/<int:leave_id>', methods=['POST'])
@login_required
def approve_leave(leave_id):
    if current_user.role == 'manager':
        leave_request = LeaveRequest.query.get(leave_id)
        leave_request.status = 'Approved'
        db.session.commit()
        flash('Leave approved!')
    return redirect(url_for('dashboard'))


@app.route('/reject_leave/<int:leave_id>', methods=['POST'])
@login_required
def reject_leave(leave_id):
    if current_user.role == 'manager':
        leave_request = LeaveRequest.query.get(leave_id)
        leave_request.status = 'Rejected'
        db.session.commit()
        flash('Leave rejected!')
    return redirect(url_for('dashboard'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


if __name__ == '__main__':
    with app.app_context():
      db.create_all()
    app.run(debug=True)