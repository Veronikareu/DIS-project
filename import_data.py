import os
import re
import sys
import time
import pandas as pd
import psycopg2
from psycopg2.extras import execute_values


DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 5432)),
    "dbname": os.getenv("DB_NAME", "cve_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
}

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

def is_valid_cve_id(cve_id: str) -> bool:
    return bool(CVE_PATTERN.match(str(cve_id).strip()))


def get_connection():
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        return conn
    except psycopg2.OperationalError as e:
        print(f"Couldnt connect to database: {e}")
        sys.exit(1)

def read_csv(filename: str) -> pd.DataFrame:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        print(f"Path not found")
        return pd.DataFrame()
    print(f"Reading {filename} ...", end=" ")
    df = pd.read_csv(path, low_memory=False)
    df.columns = [c.strip().lower() for c in df.columns]
    print(f"Rows: {len(df):,} | Collumns: {list(df.columns)}")
    return df

def safe_str(val) -> str | None:
    if pd.isna(val):
        return None
    s = str(val).strip()
    return s if s else None

def safe_float(val) -> float | None:
    try:
        return float(val) if pd.notna(val) else None
    except (ValueError, TypeError):
        return None
    
def safe_date(val) -> str |None:
    if pd.isna(val):
        return None
    try:
        return pd.to_datetime(val).strftime("%Y-%m-%d")
    except Exception:
        return None

def truncate_tables(conn):
    with conn.cursor() as cur:
        cur.execute("TRUNCATE TABLE products, vendor_product, vendors, cve RESTART IDENTITY CASCADE;")
        conn.commit()
        print("Tables have been emptied")


def import_cve(conn, df: pd.DataFrame):
    if df.empty:
        return
    
    id_col = next(
        (c for c in["unnamed: 0", "name", "cve_id", "id"] if c in df.columns),
        None
    )
    if id_col is None:
        print(f"cve.csv: cant find CVE_ID column {list(df.columns)}")
        return
    rows = []
    skipped = 0
    seen = set()

    for _, row in df.iterrows():
        cve_id = safe_str(row[id_col])
        if not cve_id or not is_valid_cve_id(cve_id):
            skipped += 1
            continue
        if cve_id in seen:
            continue
        seen.add(cve_id)

        rows.append((
            cve_id,
            safe_date(row.get("mod_date")),
            safe_date(row.get("pub_date")),
            safe_float(row.get("cvss")),
            safe_str(row.get("cwe_code")),
            safe_str(row.get("cwe_name")),
            safe_str(row.get("summary")),
            safe_str(row.get("access_authentication")),
            safe_str(row.get("access_complexity")),
            safe_str(row.get("access_vector")),
            safe_str(row.get("impact_availability")),
            safe_str(row.get("impact_confidentiality")),
            safe_str(row.get("impact_integrity")),
        ))
    
    BATCH = 1000
    total = 0

    with conn.cursor() as cur:
        for i in range(0,len(rows), BATCH):
            execute_values(cur, """
                INSERT INTO cve (
                    id, mod_date, pub_date, cvss,
                    cwe_code, cwe_name, summary,
                    access_authentication, access_complexity, access_vector,
                    impact_availability, impact_confidentiality, impact_integrity
                ) VALUES %s
                ON CONFLICT (id) DO NOTHING;
            """, rows[i:i + BATCH])
            total += len(rows[i:i + BATCH])
    conn.commit()

    if skipped:
        print(f"{skipped} rows skipped(invalid CVE_ID)")
    print(f" Inserted {total} CVE's")


def import_cve_vendor(conn, df: pd.DataFrame):
    if df.empty:
        return
 
    cve_col     = next((c for c in ["unnamed: 0", "cve_id", "name"] if c in df.columns), None)
    vendor_col = next((c for c in ["vendor", "vendor_name"] if c in df.columns and c != cve_col), None)
 
    if not cve_col or not vendor_col:
        print(f" vendors.csv: missing id/vendor columns. Found: {list(df.columns)}")
        return
 
    rows = [
        (safe_str(row[cve_col]), safe_str(row[vendor_col]))
        for _, row in df.iterrows()
        if safe_str(row[cve_col]) and safe_str(row[vendor_col])
    ]
 
    with conn.cursor() as cur:
        execute_values(cur, """
            INSERT INTO vendors (id, vendor)
            VALUES %s
            ON CONFLICT (id) DO NOTHING;
        """, rows)
    conn.commit()
    print(f"  Inserted {len(rows):,} vendors.")


def import_products(conn, df: pd.DataFrame):
    if df.empty:
        return
 
    cve_col  = next((c for c in ["cve_id", "name", "unnamed: 0"] if c in df.columns), None)
    prod_col = next((c for c in ["vulnerable_product", "product", "product_name"] if c in df.columns), None)
 
    if not cve_col or not prod_col:
        print(f"  products.csv: missing cve_id/vulnerable_product columns. Found: {list(df.columns)}")
        return
 
    rows = []
    skipped = 0
    seen = set()

    for _, row in df.iterrows():
        cve_id  = safe_str(row[cve_col])
        product = safe_str(row[prod_col])
        if not cve_id or not product:
            continue
        if not is_valid_cve_id(cve_id):
            skipped += 1
            continue
        key = ((cve_id, product))
        if key in seen:
            continue
        seen.add(key)
        rows.append(key)
 
    BATCH = 1000
    total = 0
    with conn.cursor() as cur:
        for i in range(0, len(rows), BATCH):
            execute_values(cur, """
                INSERT INTO products (cve_id, vulnerable_product)
                VALUES %s;
            """, rows[i:i + BATCH])
            total += len(rows[i:i + BATCH])
    conn.commit()
 
    if skipped:
        print(f"  {skipped} product rowsskipped (invalid CVE_ID).")
    print(f"  Inserted {total:,} products.")


def import_vendor_product(conn, df: pd.DataFrame):
    if df.empty:
        return
    
    if "unnamed: 0" not in df.columns or "vendor" not in df.columns or "product" not in df.columns:
        print(f"  vendor_product.csv: missing columns. Found: {list(df.columns)}")
        return
 
    rows = []
    for _, row in df.iterrows():
        row_id  = safe_str(row["unnamed: 0"])
        vendor  = safe_str(row["vendor"])
        product = safe_str(row["product"])
        if not row_id or not vendor or not product:
            continue
        try:
            rows.append((int(row_id), vendor, product))
        except ValueError:
            continue
 
    BATCH = 1000
    total = 0
    with conn.cursor() as cur:
        for i in range(0, len(rows), BATCH):
            execute_values(cur, """
                INSERT INTO vendor_product (id, vendor, product)
                VALUES %s;
            """, rows[i:i + BATCH])
            total += len(rows[i:i + BATCH])
    conn.commit()
    print(f"  Inserted {total:,} vendor-product rows.")


def main():
    print("=" * 60)
    print("  CVE Explorer — Data Import")
    print("=" * 60)
 
    start = time.time()
 
    print("\n[1/6] Connecting to PostgreSQL ...")
    conn = get_connection()
    print(f"  OK — '{DB_CONFIG['dbname']}' på {DB_CONFIG['host']}:{DB_CONFIG['port']}")
 
    print("\n[2/6] Emptying existing data ...")
    truncate_tables(conn)
 
    print("\n[3/6] Reading CSV-files ...")
    df_cve            = read_csv("cve.csv")
    df_vendors        = read_csv("vendors.csv")
    df_products       = read_csv("products.csv")
    df_vendor_product = read_csv("vendor_product.csv")
 
    # CVE skal indsættes FØR products (foreign key)
    print("\n[4/6] Importing CVE's ...")
    import_cve(conn, df_cve)
 
    print("\n[5/6] Importing vendors ...")
    import_cve_vendor(conn, df_vendors)
 
    print("\n[6/6] Importing vendor-product relations ...")
    import_products(conn, df_products)
    import_vendor_product(conn, df_vendor_product)
 
    conn.close()
    elapsed = time.time() - start
    print(f"\n{'=' * 60}")
    print(f"  Import completed in {elapsed:.1f} seconds.")
    print(f"{'=' * 60}")
 
 
if __name__ == "__main__":
    main()
