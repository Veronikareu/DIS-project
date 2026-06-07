import re
import os
import getpass
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, g, redirect, session, url_for, flash
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
import functools
 
load_dotenv()
 
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-in-production")

DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "dbname":   os.getenv("DB_NAME",     "cve_db"),
    "user":     os.getenv("DB_USER",     getpass.getuser()),
    "password": os.getenv("DB_PASSWORD", ""),
}
 
def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(**DB_CONFIG)
    return g.db
 
@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
 
def is_valid_cve_id(value: str) -> bool:
    return bool(CVE_PATTERN.match(value.strip()))


SEVERITY_RANGES = {
    "critical": (9.0, 10.0),
    "high":     (7.0, 8.9),
    "medium":   (4.0, 6.9),
    "low":      (0.0, 3.9),
}

def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/search")
@login_required
def index():
    db = get_db()
 
    # Get all unique vendors
    with db.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT vendor
            FROM cve_vendor
            ORDER BY vendor ASC;
        """)
        vendors = cur.fetchall()
 
    # Get all unique years
    with db.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT EXTRACT(YEAR FROM pub_date)::INTEGER AS year
            FROM cve
            WHERE pub_date IS NOT NULL
            ORDER BY year DESC;
        """)
        years = cur.fetchall()

    with db.cursor() as cur:
        cur.execute("""
            SELECT DISTINCT product
            FROM vendor_product
            ORDER BY product ASC
            LIMIT 300;
        """)
        product_list = cur.fetchall()

    # search parameters for URL
    q        = request.args.get("q", "").strip()
    vendor   = request.args.get("vendor", "").strip()
    year     = request.args.get("year", "").strip()
    severity = request.args.get("severity", "").strip()
    product  = request.args.get("product", "").strip()
 
    # Build sql
    sql = """
        SELECT DISTINCT
            c.id,
            c.pub_date,
            c.cvss,
            cv.vendor,
            c.summary
        FROM cve c
        LEFT JOIN cve_vendor cv ON c.id = cv.cve_id
        WHERE 1=1
    """
    params = []
 
    # Search cve.id or summary
    if q:
        if is_valid_cve_id(q):
            sql += " AND c.id ILIKE %s"
            params.append(f"%{q}%")
        else:
            sql += " AND c.summary ILIKE %s"
            params.append(f"%{q}%")
 
    # Vendor-filter
    if vendor:
        sql += " AND cv.vendor = %s"
        params.append(vendor)
 
    # Year-filter
    if year:
        sql += " AND EXTRACT(YEAR FROM c.pub_date) = %s"
        params.append(year)
 
    # Severity-filter via CVSS score
    if severity and severity in SEVERITY_RANGES:
        low, high = SEVERITY_RANGES[severity]
        sql += " AND c.cvss BETWEEN %s AND %s"
        params.extend([low, high])

    # Product-filter
    if product:
        sql += """ AND c.id IN (
            SELECT cve_id FROM products
            WHERE vulnerable_product ILIKE %s
        )"""
        params.append(f"%{product}%")
 
    sql += " ORDER BY c.pub_date DESC NULLS LAST LIMIT 100;"
 
    with db.cursor() as cur:
        cur.execute(sql, params)
        cves = cur.fetchall()
 
    return render_template("index.html",
        cves=cves,
        vendors=vendors,
        years=years,
        product_list=product_list,
    )

@app.route("/cve/<cve_id>")
@login_required
def cve_detail(cve_id):
    if not is_valid_cve_id(cve_id):
        return "Ugyldigt CVE-ID format", 400

    db = get_db()
    with db.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:

        cur.execute("SELECT * FROM cve WHERE id = %s;", (cve_id,))
        cve = cur.fetchone()
        if cve is None:
            return "CVE ikke fundet", 404

        cur.execute("""
            SELECT vendor FROM cve_vendor
            WHERE cve_id = %s ORDER BY vendor;
        """, (cve_id,))
        vendors = cur.fetchall()

        cur.execute("""
            SELECT vulnerable_product FROM products
            WHERE cve_id = %s ORDER BY vulnerable_product;
        """, (cve_id,))
        products = cur.fetchall()

        cur.execute(
            "SELECT id, folder FROM favorites WHERE cve_id = %s AND user_id = %s;",
            (cve_id, session["user_id"])
        )
        favorite = cur.fetchone()

        cur.execute(
            "SELECT DISTINCT folder FROM favorites WHERE user_id = %s ORDER BY folder;",
            (session["user_id"],)
        )
        folders = [row[0] for row in cur.fetchall()]

    return render_template("cve_detail.html",
        cve=cve,
        vendors=vendors,
        products=products,
        favorite=favorite,
        folders=folders,
    )

@app.route("/profile")
@login_required
def profile():
    db = get_db()
    with db.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute("""
            SELECT f.id, f.cve_id, f.folder, f.saved_at, c.cvss, c.summary
            FROM favorites f
            JOIN cve c ON f.cve_id = c.id
            WHERE f.user_id = %s
            ORDER BY f.folder, f.saved_at DESC;
        """, (session["user_id"],))
        favorites = cur.fetchall()
 
        cur.execute(
            "SELECT DISTINCT folder FROM favorites WHERE user_id = %s ORDER BY folder;",
            (session["user_id"],)
        )
        folders = [row["folder"] for row in cur.fetchall()]
 
    return render_template("profile.html", favorites=favorites, folders=folders)
 
 
@app.route("/favorite/add/<cve_id>", methods=["POST"])
@login_required
def add_favorite(cve_id):
    if not is_valid_cve_id(cve_id):
        return "Ugyldigt CVE-ID", 400
    selected = request.form.get("folder", "").strip()
    new_folder = request.form.get("new_folder", "").strip()
    if selected == "__new__" or not selected:
        folder = new_folder if new_folder else "Default"
    else:
        folder = selected
    db = get_db()
    with db.cursor() as cur:
        cur.execute("""
            INSERT INTO favorites (cve_id, folder, user_id)
            VALUES (%s, %s, %s)
            ON CONFLICT DO NOTHING;
        """, (cve_id, folder, session["user_id"]))
    db.commit()
    return redirect(request.referrer or "/")
 
 
@app.route("/favorite/remove/<int:fav_id>", methods=["POST"])
@login_required
def remove_favorite(fav_id):
    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            "DELETE FROM favorites WHERE id = %s AND user_id = %s;",
            (fav_id, session["user_id"])
        )
    db.commit()
    return redirect(request.referrer or "/profile")
 
@app.route("/")
def landing():
    if "user_id" in session:
        return redirect(url_for("index"))
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        with db.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cur.fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        flash("Incorrect username or password.")
    return render_template("login.html", mode="login")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        with db.cursor() as cur:
            try:
                cur.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (username, generate_password_hash(password))
                )
                db.commit()
                flash("Account created — sign in below.")
                return redirect(url_for("login"))
            except psycopg2.errors.UniqueViolation:
                db.rollback()
                flash("That username is already taken.")
    return render_template("login.html", mode="register")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))

if __name__ == "__main__":
    app.run(debug=True)
    