CVE Analytics ETL 🛡️
This project consists of an ETL pipeline that extracts vulnerability data (CVEs) from the NVD REST API, transforms it into a clean relational structure, and loads it into a MySQL database for analysis. It was completed as part of a Data Analysis bootcamp module evaluation. It covers API data extraction with pagination and retry logic, data cleaning and transformation, relational database design and loading, and dashboard visualization in Power BI.

Tech Stack 🔧
Python 3.14 · Jupyter Notebook · MySQL · Power BI

Libraries used:

* `requests` — HTTP requests to the NVD API, with retry and pagination handling
* `pandas` — data manipulation and DataFrame management
* `mysql-connector-python` — MySQL database connection, table creation and data loading
* `python-dotenv` — environment variable management (API key, DB password)

Project Structure 🧬

```
files/                        (generated locally — not tracked in git, see .gitignore)
├── cves.csv                  — Raw CVE data exported from the notebook (from the API)
├── cves_cleaned.csv          — Cleaned CVE data, formatted for Power BI export
├── cves_ETL.csv              — Cleaned CVE data as produced by the ETL (main.py)
├── products_raw.csv          — Raw vendor/product data exported from the notebook
├── products.csv              — Cleaned vendor/product data, consistent with cves_cleaned
└── products_ETL.csv          — Cleaned vendor/product data as produced by the ETL (main.py)

img/
└── dashboard_capture.png     — Screenshot of the final Power BI dashboard

notebooks/
└── Connection_and_EDA.ipynb  — API extraction, JSON flattening and full EDA (exploratory)

src/
├── db.py                     — Database name and table schemas (DDL)
├── extraction.py             — NVD API connection, pagination and CVE field extraction
├── functions.py               — MySQL connection, table creation and data insertion
└── transformation.py          — Data cleaning and relational transformation logic

main.py                       — Independent ETL: connects to the NVD API, transforms the
                                  data and loads it into MySQL (does not depend on the notebook)
Dashboard.pbix                 — Power BI dashboard built on top of the cleaned data
Software_Vulnerability_Exposure_Report.docx — Final summary report (objective, insights,
                                  recommendations, data dictionary)
```

Project Overview 🔩

Phase 1 — Extraction (`notebooks/Connection_and_EDA.ipynb`, `src/extraction.py`)

* Connection to the NVD REST API (`services.nvd.nist.gov`) with API key authentication
* Retry logic for temporary errors (429, 5xx) and connection/timeout exceptions
* Date-windowed pagination (120-day windows, the API's maximum range) to retrieve all CVEs published from 2021 onward
* Flattening of the nested JSON response into a flat structure per CVE: CVSS metrics with version fallback (v3.1 → v3.0 → v2.0), primary CWE weakness, and all associated vendor/product pairs

Phase 2 — EDA and Cleaning (`notebooks/Connection_and_EDA.ipynb`)

* Data quality checks: duplicates, null distribution, valid score ranges, cross-version CVSS consistency
* Removal of `Rejected` CVEs (no reliable severity data for analysis)
* Type corrections: date columns to `datetime`, CWE code extraction to nullable integer
* Description text cleanup: removal of line breaks and normalization of quotes/formula characters
* Export of both a raw and a Power-BI-ready (Spanish decimal formatting) version of the cleaned datasets

Phase 3 — Transformation (`src/transformation.py`)

* Reapplies the same cleaning logic validated in the EDA (status filtering, CWE extraction, date typing, description cleanup) so the ETL and the notebook stay in sync
* Builds the `severities` and `statuses` master/lookup tables from the unique values present in the data
* Maps `base_severity` and `vuln_status` to their corresponding foreign keys (`severity_id`, `status_id`)
* Filters the products table to keep only vendor/product rows linked to a surviving CVE

Phase 4 — Load (`src/functions.py`, `src/db.py`, `main.py`)

* Connects to a local MySQL server and creates the `cve_analytics` database if it doesn't exist
* Creates the relational schema: `severities` and `statuses` (master tables), `cves` (parent table) and `cve_products` (child table, N-to-N with `cves`)
* Loads each DataFrame into its corresponding table, sanitizing pandas null markers (`NaN`/`NA`/`NaT`) into `NULL` beforehand

Phase 5 — Dashboard (`Dashboard.pbix`)

* Power BI dashboard built on top of `cves_cleaned.csv` and `products.csv` for visual exploration of severity trends, affected vendors/products and CVE volume over time

Getting Started ▶️

1. Clone the repository

git clone https://github.com/MATC-90/bda-modulo-final-evaluacion-final-MATC-90.git

2. Install the required libraries

pip install requests pandas mysql-connector-python python-dotenv

3. Set up environment variables

Create a `.env` file in the project root with:

NVD_API_KEY=your_nvd_api_key
PASS_SQL=your_local_mysql_password

4. Run the ETL (for the MySQL database)

python main.py

This connects directly to the NVD API, downloads and cleans the CVE data, and loads it
into a local MySQL database (`cve_analytics`). It does not require the notebook to be
run first — the two are independent.

5. Run the notebook (required for the Power BI dashboard)

Open `notebooks/Connection_and_EDA.ipynb` and run it top to bottom. This performs the
API extraction, the full exploratory analysis, and generates `cves_cleaned.csv` and
`products.csv` in `files/` — the two files `Dashboard.pbix` reads from. Running this
notebook is required before opening the dashboard for the first time.
