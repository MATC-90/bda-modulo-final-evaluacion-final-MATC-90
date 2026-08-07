# =======================================================================
# DATABASE CONFIGURATION AND SCHEMAS
# =======================================================================

DB_NAME = "cve_analytics"


# MASTER TABLE: SEVERITIES
# -----------------------------------------------------------------------
SEVERITIES_TABLE = "severities"
SEVERITIES_SCHEMA = '''
    severity_id INT PRIMARY KEY,
    severity_name VARCHAR(20) NOT NULL
'''

# MASTER TABLE: VULNERABILITY STATUSES
# -----------------------------------------------------------------------
STATUSES_TABLE = "statuses"
STATUSES_SCHEMA = '''
    status_id INT PRIMARY KEY,
    status_name VARCHAR(30) NOT NULL
'''

# PARENT TABLE: CVES
# -----------------------------------------------------------------------
CVES_TABLE = "cves"
CVES_SCHEMA = '''
    cve_id VARCHAR(20) PRIMARY KEY,
    published DATETIME,
    last_modified DATETIME,
    status_id INT,
    description TEXT,
    cvss_version VARCHAR(5),
    base_score DECIMAL(3,1),
    severity_id INT,
    attack_vector VARCHAR(30),
    attack_complexity VARCHAR(30),
    privileges_required VARCHAR(30),
    user_interaction VARCHAR(30),
    confidentiality_impact VARCHAR(30),
    integrity_impact VARCHAR(30),
    availability_impact VARCHAR(30),
    exploitability_score DECIMAL(3,1),
    impact_score DECIMAL(3,1),
    cwe VARCHAR(30),
    cwe_num INT,
    num_references INT,
    FOREIGN KEY (severity_id) REFERENCES severities(severity_id),
    FOREIGN KEY (status_id) REFERENCES statuses(status_id)
'''

# CHILD TABLE: AFFECTED PRODUCTS (N-to-N relationship with cves)
# -----------------------------------------------------------------------
PRODUCTS_TABLE = "cve_products"
PRODUCTS_SCHEMA = '''
    id INT AUTO_INCREMENT PRIMARY KEY,
    cve_id VARCHAR(20),
    vendor VARCHAR(150),
    product VARCHAR(150),
    FOREIGN KEY (cve_id) REFERENCES cves(cve_id) ON DELETE CASCADE
'''