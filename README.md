# CVE Explorer

A web application for searching and exploring Common Vulnerabilities and Exposures (CVE) data.

The E/R diagram is included separately as `er_diagram.pdf` in the repository.

---

## Setup & Installation

### 1. Clone the repository

```bash
git clone <your-repo-url>
cd <repo-folder>
```

### 2. Install dependencies if nescessary 

### 3. Create the database

```bash
createdb cve_db
```

### 4. Initialize the schema

```bash
psql -d cve_db -f schema.sql
```

### 5. Import data

The CSV data files are included in the `data/` folder in the repository. Run the import script to populate the database:

```bash
python import_data.py
```

The script reads from `data/cve.csv`, `data/vendors.csv`, `data/products.csv`, and `data/vendor_product.csv`. Expect it to take a minute or two depending on hardware.

The app connects to PostgreSQL using your current system user and no password by default.

---

## Running the App

```bash
python app.py
```

The application starts on [http://127.0.0.1:5000](http://127.0.0.1:5000).

---

## Using the App

1. **Landing page** (`/`): overview with dataset statistics. Click *Sign in* to continue.
2. **Register / Login** (`/login`, `/register`): create a user account or sign in.
3. **Search** (`/search`): search CVEs by keyword or CVE ID, and filter by vendor, year, and severity (based on CVSS score).
4. **CVE detail** (`/cve/<id>`): view full details for a specific CVE including vendors, affected products, CVSS score, and CWE classification. Save to favorites from this page.
5. **My Favorites** (`/profile`): view saved CVEs organized into folders. Remove entries individually.

---

## Technical Notes

### SQL usage
The app uses SQL for all data access via `psycopg2`:
- `SELECT` with joins and filters on the search page
- `INSERT` for user registration and adding favorites
- `DELETE` for removing favorites
- `INSERT ... ON CONFLICT DO NOTHING` for idempotent data import

### Regular expression matching
CVE ID validation uses a regular expression in both `app.py` and `import_data.py`:

```python
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
```

On the search page this distinguishes CVE ID lookups from free-text summary searches. During import it is used to skip malformed rows.
