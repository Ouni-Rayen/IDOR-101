from flask import Flask, render_template, request, redirect, url_for, session, abort
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "securinets-ctf-secret-key-change-me")

# In-memory "database" of users
# IDs are not sequential on purpose
USERS = {
    100: {
        "username": "student",
        "password": "student",
        "role": "member",
        "fullname": "Alex Beginner",
        "bio": "First year cybersecurity enthusiast. Love CTFs!",
        "email": "alex@securinets.club",
        "joined": "2024-09-01",
        "secret": None
    },
    200: {
        "username": "hacker42",
        "password": "pass123",
        "role": "member",
        "fullname": "Sam Hacker",
        "bio": "Web security researcher. Always hunting for bugs.",
        "email": "sam@securinets.club",
        "joined": "2023-11-15",
        "secret": None
    },
    300: {
        "username": "crypto_cat",
        "password": "meow",
        "role": "member",
        "fullname": "Jordan Crypto",
        "bio": "Cryptography nerd. Prefer math over web vulns.",
        "email": "jordan@securinets.club",
        "joined": "2024-01-20",
        "secret": None
    },
    400: {
        "username": "pwn_master",
        "password": "shell",
        "role": "member",
        "fullname": "Taylor Pwn",
        "bio": "Binary exploitation specialist.",
        "email": "taylor@securinets.club",
        "joined": "2023-08-10",
        "secret": None
    },
    584: {
        "username": "admin",
        "password": "sup3r_s3cr3t_4dm1n_p4ss",  # not needed for the challenge
        "role": "admin",
        "fullname": "Securinets Admin",
        "bio": "Club administrator. Keeper of the secrets.",
        "email": "admin@securinets.club",
        "joined": "2020-01-01",
        "secret": "Securinets{1d0r_n0t_s0_h4rd_4ft3r_4ll}"
    }
}

# Public member IDs shown on the members page (admin is hidden)
PUBLIC_MEMBERS = [100, 200, 300, 400]


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        for uid, user in USERS.items():
            if user["username"] == username and user["password"] == password:
                session["user_id"] = uid
                session["username"] = user["username"]
                return redirect(url_for("dashboard"))

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = USERS.get(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user, user_id=session["user_id"])


@app.route("/members")
def members():
    if "user_id" not in session:
        return redirect(url_for("login"))

    public_users = []
    for uid in PUBLIC_MEMBERS:
        u = USERS[uid]
        public_users.append({
            "id": uid,
            "fullname": u["fullname"],
            "username": u["username"],
            "role": u["role"],
            "joined": u["joined"]
        })

    return render_template("members.html", members=public_users)


@app.route("/profile/<int:profile_id>")
def profile(profile_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    # IDOR vulnerability: no ownership / authorization check!
    # Any logged-in user can view any profile by changing the ID
    target = USERS.get(profile_id)
    if not target:
        abort(404)

    return render_template("profile.html", profile=target, profile_id=profile_id)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
