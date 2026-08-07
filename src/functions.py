# =======================================================================
# IMPORTS FOR FUNCTIONS
# =======================================================================

# Data processing
# -----------------------------------------------------------------------
import pandas as pd

# MySQL Connection
# -----------------------------------------------------------------------
import mysql.connector
from mysql.connector import Error 

# Environment variables
# -----------------------------------------------------------------------
import os 
from dotenv import load_dotenv
load_dotenv()
sql_password = os.getenv("PASS_SQL")

# =======================================================================
# DECORATOR: Function wrapper
# =======================================================================

def requires_connection(original_function):
    def wrapper(connection, *args, **kwargs):
        if connection is None:
            print(f"Error: No active connection to execute '{original_function.__name__}'")
            return None
        return original_function(connection, *args, **kwargs)
    return wrapper


# =======================================================================
# MySQL FUNCTIONS
# =======================================================================

# -----------------------------------------------------------------------
# Establishes a connection with the local MySQL server
# -----------------------------------------------------------------------
def mysql_connection():

    try:
        # Using the library connector
        connection = mysql.connector.connect(
            host="127.0.0.1",
            user="root",
            password=sql_password,  # Uses the local environment password variable, omitted from GitHub
            # Note: Creating a new database, so database name is not specified here
        )
        print("Successful connection")
        return connection
    
    # Handles any database-related error that occurs during connection
    except Error as e:
        print(f"An error has occurred: {e}")


# -----------------------------------------------------------------------
# Creates a new database if it does not exist
# -----------------------------------------------------------------------
@requires_connection
def create_database(connection, db_name):
    
    try:
        # Opens the cursor safely using a context manager to ensure automatic closure
        with connection.cursor() as cursor:
            query = f"CREATE DATABASE IF NOT EXISTS {db_name}"
            # Executes the database creation query
            cursor.execute(query)
            print("Query successful")

    # Catches any SQL execution error
    except Error as e:
        print(f"Error creating database: {e}")


# -----------------------------------------------------------------------
# Function to drop the database if necessary
# -----------------------------------------------------------------------
@requires_connection
def drop_database(connection, db_name):

    try:
        # Prompts user for confirmation
        user_response = input(f"The database '{db_name}' will be dropped. Are you sure? (Y/N):").upper()
        # Proceeds only upon confirmation
        if user_response == "Y":
            with connection.cursor() as cursor:
                cursor.execute(f"DROP DATABASE IF EXISTS {db_name}")
                connection.commit()
                print(f"Database {db_name} successfully deleted")
        else:
            # Any other input cancels the deletion
            print("Operation cancelled")
    
    # Catches potential MySQL errors
    except Error as e:
        print(f"Error deleting database: {e}")


# -----------------------------------------------------------------------
# Creates a generic table within the specified database if it does not exist
# -----------------------------------------------------------------------
@requires_connection
def create_generic_table(connection, db_name, table_name, table_schema):
    
    try:
        # Opens the cursor safely using a context manager to ensure automatic closure
        with connection.cursor() as cursor:
            cursor.execute(f"USE {db_name};")
            # Defines the SQL query for the generic table
            query = f''' CREATE TABLE IF NOT EXISTS {table_name} ({table_schema});'''
            # Executes the table creation query
            cursor.execute(query)
            print("Creation query successful")
    
    # Catches any SQL execution error
    except Error as e:
        print(f"Error creating table: {e}")


# -----------------------------------------------------------------------
# Function to drop tables if necessary
# -----------------------------------------------------------------------
@requires_connection
def drop_table(connection, db_name, table_name):

    try:

        # Checks if user confirmed the operation
        user_response = input(f"The table '{table_name}' will be dropped. Are you sure? (Y/N):").upper()
        if user_response == "Y":
            # Opens the cursor safely using a context manager to ensure automatic closure
            with connection.cursor() as cursor:
                # Selects the database passed as an argument
                cursor.execute(f"USE {db_name};")
                # Defines the SQL query to drop the table if it exists
                query = f'''DROP TABLE IF EXISTS {table_name}'''
                # Executes the table drop query
                cursor.execute(query)
                connection.commit()
                print("Table successfully deleted")
        else: 
            print("Operation cancelled")

    # Catches any SQL execution error
    except Error as e:
        print(f"Error deleting table: {e}")


# -----------------------------------------------------------------------
# Inserts data from a cleaned DataFrame into the corresponding table
# -----------------------------------------------------------------------
@requires_connection
def insert_data(connection, db_name, table_name, df):
    
    try:
        # Replace pandas null markers (NaN, pd.NA, NaT) with Python None,
        # since mysql-connector cannot serialize pandas' native null types
        # (e.g. pd.NA from nullable Int64 columns raises "NAType cannot be converted")
        df_sanitized = df.astype(object).where(df.notna(), None)

        # Converts DataFrame rows into a list of tuples
        df_values = df_sanitized.values.tolist()
        
        # Dynamic generation of the SQL query based on DataFrame columns
        columns = ", ".join(df.columns)
        placeholders = ", ".join(["%s"] * len(df.columns))
        
        query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"

        with connection.cursor() as cursor:
            cursor.execute(f"USE {db_name};")
            # Insert records one row at a time using true parameterized execute().

            for row in df_values:
                cursor.execute(query, row)
            connection.commit()
            print(f"Insertion successful: {len(df_values)} records added to table '{table_name}'.")

    # Catches SQL execution errors        
    except Error as e:
        print(f"Error inserting data into table {table_name}: {e}")