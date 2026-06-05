import psycopg2

def get_connection():
    return psycopg2.connect(dbname="cve_db")
