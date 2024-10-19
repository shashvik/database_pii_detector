import mysql.connector
import pandas as pd
import re
from pii_patterns import (
    extracted_patterns,
    extracted_criticality,
    extracted_compliance_standards  # Import compliance standards
)

# Database connection details
DB_CONFIG = {
    'user': 'your_username',
    'password': 'your_password',
    'host': 'localhost',
    'database': 'your_database',
}

def scan_database():
    # Connect to the database
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    # Get all tables
    cursor.execute("SHOW TABLES")
    tables = cursor.fetchall()

    results = []

    # Scan each table
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT * FROM {table_name} LIMIT 100")  # Limit to first 100 rows for scanning
        rows = cursor.fetchall()
        
        # Get column names
        column_names = [i[0] for i in cursor.description]

        for column in column_names:
            # Initialize a dictionary to hold PII types and their row numbers
            pii_data = {}

            for row_index, row in enumerate(rows):
                sample_data = str(row[column_names.index(column)]) if row[column_names.index(column)] is not None else ''
                for pii_type, pattern in extracted_patterns.items():
                    if re.search(pattern, sample_data):
                        # Append the row number to the corresponding PII type
                        if pii_type not in pii_data:
                            pii_data[pii_type] = []
                        pii_data[pii_type].append(row_index + 1)  # Store row number (1-based index)

            # Add results to the list
            for pii_type, row_numbers in pii_data.items():
                criticality = extracted_criticality[pii_type]
                compliance_standards = extracted_compliance_standards[pii_type]  # Get compliance standards
                results.append({
                    'Table Name': table_name,
                    'Column Name': column,
                    'PII Type': pii_type,
                    'Criticality': criticality,
                    'Compliance Standards': compliance_standards,  # Add compliance standards
                    'Row Numbers': ', '.join(map(str, row_numbers))  # Join row numbers as a string
                })

    # Close the database connection
    cursor.close()
    conn.close()

    # Create DataFrame and write to Excel
    df = pd.DataFrame(results)
    df.to_excel('pii_data_identification_with_compliance.xlsx', index=False)
    print('PII data classification written to pii_data_identification_with_compliance.xlsx')

if __name__ == "__main__":
    scan_database()
