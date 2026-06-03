CREATE TABLE cve (
    id VARCHAR PRIMARY KEY,
    mod_date DATE,
    pub_date DATE,
    cvss FLOAT,
    cwe_code VARCHAR,
    cwe_name VARCHAR,
    summary TEXT,
    access_authentication VARCHAR,
    access_complexity VARCHAR,
    access_vector VARCHAR,
    impact_availability VARCHAR,
    impact_confidentiality VARCHAR,
    impact_integrity VARCHAR
);

CREATE TABLE vendors (
    id VARCHAR PRIMARY KEY,
    vendor VARCHAR
);

CREATE TABLE products (
    cve_id VARCHAR REFERENCES cve(id),
    vulnerable_product VARCHAR,
    PRIMARY KEY (cve_id, vulnerable_product)
);

CREATE TABLE vendor_product (
    id INTEGER PRIMARY KEY,
    vendor VARCHAR,
    product VARCHAR
);
