
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

![image](https://github.com/user-attachments/assets/02db3bd2-7c7f-44df-84d4-b9ab85bc5289)



## Acknowledgments

- The regex patterns for PII detection are derived from various sources and can be adjusted to suit specific requirements.
- Special thanks to the contributors and maintainers of the libraries used in this project.




# Postgres Audit Log Analyzer

## Overview
The **PostgresAuditAnalyzer** is a Python script designed to parse and analyze Postgres audit log data for compliance, sensitive data operations, error patterns, user activity, and suspicious behavior. It can generate a detailed compliance report based on the audit log data.

### Features
- Parse raw Postgres audit log entries
- Detect sensitive data operations (e.g., password, credit card, ssn, etc.)
- Analyze user activity patterns and error messages
- Generate compliance reports with metrics for failed operations, delete operations, and suspicious activity
- Print unique user commands and queries
- Generate alerts based on specific compliance rules (e.g., high number of failed operations or multiple IP access by a user)

## Installation
Ensure you have Python 3 installed. You also need to install the following dependencies:

```bash
pip install pandas
```

## Usage

1. **Prepare Postgres Audit Log File:**
   * Ensure the Postgres audit log data is in CSV format. Each line should represent one log entry with the following fields:
      1. Timestamp
      2. User
      3. Database
      4. Process ID
      5. Connection Info (IP address will be extracted)
      6. Session ID
      7. Line Number
      8. Command Tag (e.g., `SELECT`, `UPDATE`, `DELETE`, `INSERT`)
      9. Session Start Time
      10. Virtual Transaction ID
      11. Transaction ID
      12. Message Type
      13. Error Code
      14. Message
      15. Query (optional, if present)

2. **Run the Script:**
   To run the script and generate a compliance report, use the following command:

   ```bash
   python script.py <path_to_log_file>
   ```

   Example:
   ```bash
   python script.py postgres_audit_log.txt
   ```

   This will:
   * Parse the log file
   * Analyze sensitive data operations, error patterns, user activity, and compliance metrics
   * Print unique user commands
   * Generate a JSON-based compliance report saved in the current directory

3. **Output:**
   * A JSON compliance report will be saved with the name `compliance_report_<timestamp>.json`
   * The report includes:
      * Summary of total operations, failed operations, and delete operations
      * User activity analysis
      * Detailed report of sensitive data operations and error patterns
      * Compliance alerts (e.g., high number of failed operations, multiple IP access by a user)

4. **Example Output:**
   ```text
   Compliance Analysis Report generated: compliance_report_20231019_123456.json

   Key Compliance Metrics:
   Analysis Period: 2023-10-19T12:00:00 to 2023-10-19T13:00:00
   Total Operations: 120
   Failed Operations: 15
   Delete Operations: 5
   Unique Users: 10
   Unique IPs: 8

   Compliance Alerts:
   [HIGH] Failed Operations
   Description: High number of failed operations (7) from IP 192.168.1.10
   Recommendation: Investigate potential unauthorized access attempts

   [MEDIUM] Multiple IP Access
   Description: User john accessed from 4 different IPs
   Recommendation: Verify if multiple IP access is authorized

   [MEDIUM] Delete Operations
   Description: High number of delete operations (6) by user admin
   Recommendation: Review delete operation patterns
   ```

## Code Structure

### Class: `PostgresAuditAnalyzer`
* `__init__(self, log_data: str)`: Initializes the analyzer with raw log data
* `_parse_log_data()`: Parses the raw log into structured log entries
* `analyze_sensitive_data_operations()`: Analyzes the audit logs for sensitive data-related queries
* `analyze_error_patterns()`: Analyzes the log entries for error message patterns
* `analyze_user_activity()`: Tracks and analyzes user operations
* `analyze_compliance_metrics()`: Gathers compliance metrics like failed attempts and deletions
* `generate_compliance_report()`: Generates a full compliance report
* `print_unique_commands()`: Prints a table of unique commands made by users

### Functions
* `main(log_file_path: str)`: The main function to run the compliance analysis. It reads the log file, runs the analysis, and saves the generated report.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
