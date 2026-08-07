# Data processing
import pandas as pd

# Custom modules
import src.functions as fn
import src.db as db
import src.transformation as tr

# Environment variables
import os
from dotenv import load_dotenv

load_dotenv()
sql_password = os.getenv("PASS_SQL")


# =======================================================================
# MAIN LOADING SCRIPT (ETL)
# =======================================================================

# -----------------------------------------------------------------------
# 1. EXTRACTION (Extract)
# -----------------------------------------------------------------------
print("Loading raw CSV data...")
df_cves_raw = pd.read_csv("files/cves.csv")
df_products_raw = pd.read_csv("files/products_raw.csv")


# -----------------------------------------------------------------------
# 2. TRANSFORMATION (Transform)
# -----------------------------------------------------------------------
print("Applying full cleaning and relational transformations...")
df_severities, df_statuses, df_cves_final, df_products_final = tr.transform_cve_data(df_cves_raw, df_products_raw)
print("Transformation completed successfully!")


# -----------------------------------------------------------------------
# 3. LOADING (Load)
# -----------------------------------------------------------------------
print("\n--- Starting load process in MySQL ---")

# Step 1: Connection
connection = fn.mysql_connection()

# Step 2: Database setup
fn.create_database(connection, db.DB_NAME)

# Step 3: Table creation
print("\nCreating table structures...")
fn.create_generic_table(connection, db.DB_NAME, db.SEVERITIES_TABLE, db.SEVERITIES_SCHEMA)
fn.create_generic_table(connection, db.DB_NAME, db.STATUSES_TABLE, db.STATUSES_SCHEMA)
fn.create_generic_table(connection, db.DB_NAME, db.CVES_TABLE, db.CVES_SCHEMA)
fn.create_generic_table(connection, db.DB_NAME, db.PRODUCTS_TABLE, db.PRODUCTS_SCHEMA)

# Step 4: Data Insertion
print("\nInserting data into corresponding tables...")
fn.insert_data(connection, db.DB_NAME, db.SEVERITIES_TABLE, df_severities)
fn.insert_data(connection, db.DB_NAME, db.STATUSES_TABLE, df_statuses)
fn.insert_data(connection, db.DB_NAME, db.CVES_TABLE, df_cves_final)
fn.insert_data(connection, db.DB_NAME, db.PRODUCTS_TABLE, df_products_final)

print("\n--- Load process completed successfully! ---")