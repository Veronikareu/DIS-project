import re
import os
import psycopg2
import psycopg2.extras
from flask import Flask, render_template, request, g
from dotenv import load_dotenv
 
load_dotenv()
 
app = Flask(__name__)

DB_CONFIG = {
    "host":     os.getenv("DB_HOST",     "localhost"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "dbname":   os.getenv("DB_NAME",     "cve_db"),
    "user":     os.getenv("DB_USER",     "postgres"),
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


@app.route("/")
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
 
    # search parameters for URL
    q        = request.args.get("q", "").strip()
    vendor   = request.args.get("vendor", "").strip()
    year     = request.args.get("year", "").strip()
    severity = request.args.get("severity", "").strip()
 
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
 
    sql += " ORDER BY c.pub_date DESC NULLS LAST LIMIT 100;"
 
    with db.cursor() as cur:
        cur.execute(sql, params)
        cves = cur.fetchall()
 
    return render_template("index.html",
        cves=cves,
        vendors=vendors,
        years=years,
    )

@app.route("/cve/<cve_id>")
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
 
    return render_template("cve_detail.html",
        cve=cve,
        vendors=vendors,
        products=products,
    )

if __name__ == "__main__":
    app.run(debug=True)