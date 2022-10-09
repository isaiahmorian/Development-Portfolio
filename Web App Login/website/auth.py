#authentication/login
from dataclasses import dataclass
from hashlib import sha256
from unicodedata import category
from flask import Blueprint, render_template, flash, redirect, url_for
from flask import request
from more_itertools import first
from website import views, db

from website.models import User
from werkzeug.security import generate_password_hash, check_password_hash


auth = Blueprint('auth', __name__)


@auth.route('/login', methods = ["GET","POST"])
def login():
    data = request.form 
    print(data)
    return render_template('login.html', text = "Testing the website", user = "Isaiah")


@auth.route('/logout')
def logout():
    return render_template('logout.html')

@auth.route('/portfolio')
def portfolio():
    return render_template('portfolio.html')

@auth.route('/resume')
def resume():
    return render_template('resume.html')


@auth.route('/signup', methods = ["GET","POST"])        
def signup():
    if request.method == "POST": 
        email = request.form.get('email')
        first_name = request.form.get('first_name')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')
        if len(email) < 4:
             flash('Email must be longer than 3 characters.',category='error')
        elif len(first_name) < 2:
            flash('First name must be longer than 1 character.', category= 'error')
        elif password1!= password2:
            flash('Passwords do not match.',category='error')
        elif len(password1) < 8:
            flash('Password must be at least 8 characters.',category='error')
        else:
            new_user = User(email=email, first_name = first_name, password=generate_password_hash(password1, method='sha256')) 
            db.session.add(new_user)
            db.session.commit()
            flash('Account created', category='success')
            return redirect(url_for('views.home'))

    
    return render_template('signup.html')


