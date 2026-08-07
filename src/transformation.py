# Data processing
# -----------------------------------------------------------------------
import pandas as pd


# -----------------------------------------------------------------------
# Converts a list of raw CVE items into a flat DataFrame
# -----------------------------------------------------------------------
def build_cves_dataframe(raw_cves, extract_function):

    flat_cves = [extract_function(item) for item in raw_cves]
    df_cves = pd.DataFrame(flat_cves)

    return df_cves


# -----------------------------------------------------------------------
# Builds the secondary vendor/product table from the vendors_products column
# NOTE: only needed when starting from the raw extraction output (where
# vendors_products still exists as a list column). When loading from the
# already-exported CSVs (files/cves.csv + files/products_raw.csv), the
# products table is already split into vendor/product and this function
# is not called.
# -----------------------------------------------------------------------
def build_products_dataframe(df_cves):

    df_products = df_cves[["cve_id", "vendors_products"]].explode("vendors_products")
    df_products = df_products.dropna(subset=["vendors_products"])

    df_products[["vendor", "product"]] = pd.DataFrame(
        df_products["vendors_products"].tolist(), index=df_products.index
    )

    df_products = df_products.drop(columns=["vendors_products"])
    df_products = df_products.drop_duplicates()
    df_products = df_products.reset_index(drop=True)

    return df_products


# -----------------------------------------------------------------------
# Cleans the description text field (same logic as the EDA notebook):
# removes internal line breaks, normalizes double quotes to single quotes,
# and escapes leading formula characters so the text is safe to export/insert.
# -----------------------------------------------------------------------
def clean_descriptions(df):

    df = df.copy()

    # Remove internal line breaks (carriage returns and newlines) from description
    df["description"] = (
        df["description"]
        .astype(str)
        .str.replace(r"[\r\n]+", " ", regex=True)
        .str.strip()
    )

    # Replace internal double quotes with single quotes to prevent CSV/SQL issues
    df["description"] = df["description"].str.replace('"', "'")

    # Escape leading formula characters (=, +, -, @) to prevent spreadsheet injection
    df["description"] = df["description"].apply(
        lambda x: f"'{x}" if x.startswith(("=", "+", "-", "@")) else x
    )

    return df


# -----------------------------------------------------------------------
# Applies all cleaning decisions validated during the EDA
# -----------------------------------------------------------------------
def clean_cves_dataframe(df_cves):

    df = df_cves.copy()

    # Drop Rejected CVEs: no reliable severity/data for analysis
    df = df[df["vuln_status"] != "Rejected"]

    # Extract numeric CWE code, keeping NaN for "Other"/"noinfo"/missing
    df["cwe_num"] = df["cwe"].str.extract(r"CWE-(\d+)")
    df["cwe_num"] = df["cwe_num"].astype("Int64")

    # Convert date columns to real datetime type
    df["published"] = pd.to_datetime(df["published"])
    df["last_modified"] = pd.to_datetime(df["last_modified"])

    # Clean description text (line breaks, quotes, formula-injection characters)
    df = clean_descriptions(df)

    return df

# -----------------------------------------------------------------------
# Generates master lookup tables for severities and statuses
# -----------------------------------------------------------------------
def build_master_tables(df_cves_clean):

    # Severities master table
    unique_severities = df_cves_clean["base_severity"].dropna().unique()
    df_severities = pd.DataFrame({
        "severity_id": range(1, len(unique_severities) + 1),
        "severity_name": unique_severities
    })

    # Statuses master table
    unique_statuses = df_cves_clean["vuln_status"].dropna().unique()
    df_statuses = pd.DataFrame({
        "status_id": range(1, len(unique_statuses) + 1),
        "status_name": unique_statuses
    })

    return df_severities, df_statuses


# -----------------------------------------------------------------------
# Full transformation process for the relational database
# -----------------------------------------------------------------------
def transform_cve_data(df_cves, df_products):

    # Clean main CVEs DataFrame
    df_cves_clean = clean_cves_dataframe(df_cves)

    # Build lookup tables
    df_severities, df_statuses = build_master_tables(df_cves_clean)

    # Map foreign keys (IDs) back to main CVE DataFrame
    df_extended = pd.merge(df_cves_clean, df_severities, left_on="base_severity", right_on="severity_name", how="left")
    df_extended = pd.merge(df_extended, df_statuses, left_on="vuln_status", right_on="status_name", how="left")

    # Final column selection
    cves_columns = [
        "cve_id", "published", "last_modified", "status_id", "description",
        "cvss_version", "base_score", "severity_id", "attack_vector", "attack_complexity",
        "privileges_required", "user_interaction", "confidentiality_impact",
        "integrity_impact", "availability_impact", "exploitability_score",
        "impact_score", "cwe", "cwe_num", "num_references"
    ]
    df_cves_final = df_extended[cves_columns].copy()

    # Filter products table to maintain consistency (remove orphan products)
    df_products_final = df_products[df_products["cve_id"].isin(df_cves_final["cve_id"])][["cve_id", "vendor", "product"]].copy()

    return df_severities, df_statuses, df_cves_final, df_products_final