import os
import sqlite3
import secrets
from datetime import datetime, timedelta, timezone
from passlib.hash import pbkdf2_sha256
from functools import wraps

import jwt
from flask import request, g, render_template

SECRET = os.getenv("SECRET")


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not logged_in():
            return render_template("login.html")
        print("user is logged in already")
        return func(*args, **kwargs)

    return wrapper


def get_user_with_credentials(email, password):
    try:
        con = sqlite3.connect("bank.db")
        cur = con.cursor()
        cur.execute(
            """
            SELECT email, name, password FROM users where email=?""",
            (email,),
        )
        row = cur.fetchone()

        """
        USER ENUMERATION / TIMING ATTACKS:
        We create a random, fake "password" to pass to verify() even if we don't have a real
        password to check the inserted password against.
        """
        if row is None:
            row = ["fake", "fake", pbkdf2_sha256.hash(secrets.token_hex(16))]
        email, name, hash = row
        if not pbkdf2_sha256.verify(password, hash):
            return None
        return {"email": email, "name": name, "token": create_token(email)}
    finally:
        con.close()


def logged_in():
    token = request.cookies.get("auth_token")
    try:
        data = jwt.decode(token, SECRET, algorithms=["HS256"])
        g.user = data["sub"]
        return True
    except jwt.InvalidTokenError:
        return False


def create_token(email):
    now = datetime.now(timezone.utc)
    payload = {"sub": email, "iat": now, "exp": now + timedelta(minutes=60)}
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    return token
