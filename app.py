import os
from flask import (
    Flask,
    flash,
    request,
    make_response,
    redirect,
    render_template,
    g,
    abort,
    send_from_directory,
)
import random

from user_service import get_user_with_credentials, login_required
from account_service import do_transfer, get_balance, get_user_accounts
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET")

"""
CSRF: Flask_WTF gives us the CSRFProtect() function. With it, we can include a "csrf_token"
input in every form in our app. If the csrf_token is missing from the form, it will not be submitted.
"""
csrf = CSRFProtect(app)


@app.route("/assets/<path:filename>")
def serve_assets(filename):
    return send_from_directory(os.path.join(app.root_path, "assets"), filename)


@app.route("/", methods=["GET"])
@login_required
def home():
    return redirect("/dashboard")


@app.route("/login", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    user = get_user_with_credentials(email, password)
    if not user:
        return render_template("login.html", error="Invalid credentials")
    response = make_response(redirect("/dashboard"))
    response.set_cookie("auth_token", user["token"])
    return response, 303


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    return render_template("dashboard.html", email=g.user)


@app.route("/accounts", methods=["GET"])
@login_required
def accounts():
    user_accounts = get_user_accounts(g.user)
    return render_template("accounts.html", email=g.user, accounts=user_accounts)


@app.route("/details", methods=["GET"])
@login_required
def details():
    account_number = request.args["account"]
    return render_template(
        "details.html",
        user=g.user,
        account_number=account_number,
        balance=get_balance(account_number, g.user),
    )


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "GET":
        return render_template("transfer.html", user=g.user)

    source = request.form.get("from")
    target = request.form.get("to")

    """
    XSS: We already restrict inputs from the client, but as always we make sure to check them again
    on the server. We drop abort in favor of rerendering to display errors instead.
    """
    try:
        amount = int(request.form.get("amount"))
    except ValueError:
        return render_template(
            "transfer.html", error="Incorrect input format for transfer amount."
        )

    if amount < 1:
        return render_template("transfer.html", error="Must trade at least 1 mineral.")
    if amount > 1000:
        return render_template(
            "transfer.html", error="Cannot trade more than 999 minerals at once."
        )

    available_balance = get_balance(source, g.user)
    if available_balance is None:
        return render_template("transfer.html", error="Account not found.")
    if amount > available_balance:
        return render_template("transfer.html", error="You have not enough minerals!")

    if do_transfer(source, target, amount):
        flash("Mineral transfer complete!")
    else:
        return render_template(
            "transfer.html",
            error=f'Warp interrupted by enemy {"Terran" if random.randint(0,1) == 0 else "Zerg"}! Try again later.',
        )

    response = make_response(redirect("/dashboard"))
    return response, 303


@app.route("/logout", methods=["GET"])
def logout():
    response = make_response(redirect("/dashboard"))
    response.delete_cookie("auth_token")
    return response, 303
