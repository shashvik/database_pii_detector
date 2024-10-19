
# Database PII Detector

## Overview

The **Database PII Detector** is a Python application designed to scan databases for Personally Identifiable Information (PII). It identifies sensitive data types such as email addresses, phone numbers, Social Security Numbers (SSNs), credit card numbers, and other critical information, providing insights into potential compliance violations.

## Features

- **Regex-based Detection**: Utilizes regex patterns to identify various types of PII in database columns.
- **Criticality Classification**: Classifies PII based on its sensitivity level.
- **Compliance Mapping**: Provides information on compliance standards related to identified PII.
- **Output in Excel**: Results are exported to an Excel file for easy reporting and analysis.

## Prerequisites

- Python 3.x
- MySQL Connector for Python or psycopg2 for PostgreSQL
- pandas library
- OpenPyXL library for Excel output

You can install the required libraries using:

```bash
pip install mysql-connector-python pandas openpyxl
```

or for PostgreSQL:

```bash
pip install psycopg2 pandas openpyxl
```

## Setup

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-username/database-pii-detector.git
   cd database-pii-detector
   ```

2. **Database Configuration**:
   Modify the `DB_CONFIG` dictionary in the `pii_data_identifier.py` file to include your database connection details:

   For MySQL:
   ```python
   db_config = {
       'host': 'your-database-host',
       'user': 'your-database-username',
       'password': 'your-database-password',
       'database': 'your-database-name'
   }
   ```

   For PostgreSQL:
   ```python
   DB_CONFIG = {
       'user': 'your_username',
       'password': 'your_password',
       'host': 'localhost',
       'port': 5432,  # Default PostgreSQL port
       'database': 'your_database',
   }
   ```

3. **Define PII Patterns**:
   Edit the `pii_patterns.py` file to modify or add more PII detection patterns and their corresponding criticality levels and compliance standards.

## Usage

Run the script to scan the database for PII:

```bash
python pii_data_identifier.py
```

Upon execution, the program will:
- Connect to the specified database (MySQL or PostgreSQL).
- Scan each table and column for PII using the defined regex patterns.
- Compile the findings, including table names, column names, criticality levels, and compliance violations.
- Export the results to an Excel file named `pii_detection_report.xlsx`.

## Output

The output Excel file contains the following columns:
- **Table Name**: The name of the table where PII was found.
- **Column Name**: The name of the column containing PII.
- **PII Type**: The type of PII detected (e.g., email, phone number).
- **Criticality**: The criticality level of the detected PII.
- **Compliance Standards**: Relevant compliance standards related to the PII type.
- **Row Numbers**: The row numbers in the corresponding tables where PII was found.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- The regex patterns for PII detection are derived from various sources and can be adjusted to suit specific requirements.
- Special thanks to the contributors and maintainers of the libraries used in this project.
