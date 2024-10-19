import pandas as pd
from datetime import datetime
import re
import json
from collections import Counter, defaultdict
from typing import List, Dict, Tuple
from ipaddress import ip_address, IPv4Address, IPv6Address

class PostgresAuditAnalyzer:
    def __init__(self, log_data: str):
        self.raw_data = log_data
        self.log_entries = self._parse_log_data()
        
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp string with error handling for malformed dates."""
        try:
            # First attempt: standard parsing
            return datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            # Handle case where year is missing first digit
            if re.match(r'\d{3}-\d{2}-\d{2}', timestamp_str):
                fixed_timestamp = '2' + timestamp_str
                return datetime.strptime(fixed_timestamp.split('.')[0], '%Y-%m-%d %H:%M:%S')
            raise

    def _parse_log_data(self) -> List[Dict]:
        """Parse the raw log data into structured format."""
        entries = []
        for line in self.raw_data.split('\n'):
            if line.strip():
                fields = line.split(',')
                if len(fields) >= 10:
                    # Extract IP address from connection info
                    connection_info = fields[4].strip('"')
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', connection_info)
                    ip_address = ip_match.group(1) if ip_match else None
                    
                    try:
                        entry = {
                            'timestamp': self._parse_timestamp(fields[0]),
                            'user': fields[1].strip('"'),
                            'database': fields[2].strip('"'),
                            'process_id': fields[3],
                            'ip_address': ip_address,
                            'connection_info': connection_info,
                            'session_id': fields[5],
                            'line_num': fields[6],
                            'command_tag': fields[7].strip('"'),
                            'session_start_time': fields[8],
                            'virtual_transaction_id': fields[9],
                            'transaction_id': fields[10],
                            'message_type': fields[11].strip('"'),
                            'error_code': fields[12].strip('"'),
                            'message': fields[13].strip('"'),
                            'query': fields[19].strip('"') if len(fields) > 19 else None
                        }
                        entries.append(entry)
                    except (ValueError, IndexError) as e:
                        print(f"Warning: Skipping malformed log entry: {line[:100]}... Error: {str(e)}")
                        continue
        return entries

    def analyze_sensitive_data_operations(self) -> Dict:
        """Analyze operations related to sensitive data."""
        sensitive_patterns = [
            r'(?i)password',
            r'(?i)credit.*card',
            r'(?i)ssn',
            r'(?i)social.*security',
            r'(?i)personal.*data',
            r'(?i)confidential',
            r'(?i)private',
            r'(?i)secret'
        ]
        
        analysis = {
            'sensitive_operations': {
                'total': 0,
                'by_user': defaultdict(int),
                'by_type': defaultdict(int),
                'by_operation': defaultdict(int)
            },
            'suspicious_queries': []
        }
        
        for entry in self.log_entries:
            if entry['query']:
                # Check if query contains sensitive patterns
                for pattern in sensitive_patterns:
                    if re.search(pattern, entry['query']):
                        analysis['sensitive_operations']['total'] += 1
                        analysis['sensitive_operations']['by_user'][entry['user']] += 1
                        
                        # Determine operation type
                        operation = 'OTHER'
                        if 'SELECT' in entry['query'].upper():
                            operation = 'SELECT'
                        elif 'UPDATE' in entry['query'].upper():
                            operation = 'UPDATE'
                        elif 'DELETE' in entry['query'].upper():
                            operation = 'DELETE'
                        elif 'INSERT' in entry['query'].upper():
                            operation = 'INSERT'
                        
                        analysis['sensitive_operations']['by_operation'][operation] += 1
                        
                        # Add suspicious queries (e.g., mass updates/deletes on sensitive data)
                        if (operation in ['UPDATE', 'DELETE'] and 
                            'WHERE' not in entry['query'].upper()):
                            analysis['suspicious_queries'].append({
                                'timestamp': entry['timestamp'].isoformat(),
                                'user': entry['user'],
                                'query': entry['query'],
                                'reason': f'Mass {operation} on sensitive data without WHERE clause'
                            })
                        break  # Count each query only once even if it matches multiple patterns
        
        # Convert defaultdict to regular dict for JSON serialization
        analysis['sensitive_operations']['by_user'] = dict(analysis['sensitive_operations']['by_user'])
        analysis['sensitive_operations']['by_operation'] = dict(analysis['sensitive_operations']['by_operation'])
        
        return analysis


    def analyze_error_patterns(self) -> Dict:
        """Analyze patterns in error messages."""
        errors = [entry for entry in self.log_entries if entry['message_type'] == 'ERROR']
        error_types = Counter([error['error_code'] for error in errors])
        error_messages = Counter([error['message'] for error in errors])
        
        return {
            'total_errors': len(errors),
            'error_types': dict(error_types),
            'error_messages': dict(error_messages)
        }
    
    def analyze_user_activity(self) -> Dict:
        """Analyze user activity patterns."""
        user_ops = {}
        for entry in self.log_entries:
            if entry['user']:
                if entry['user'] not in user_ops:
                    user_ops[entry['user']] = []
                user_ops[entry['user']].append({
                    'timestamp': entry['timestamp'],
                    'operation': entry['command_tag'],
                    'message_type': entry['message_type']
                })
        
        user_stats = {}
        for user, ops in user_ops.items():
            user_stats[user] = {
                'total_operations': len(ops),
                'operation_types': Counter([op['operation'] for op in ops]),
                'error_count': len([op for op in ops if op['message_type'] == 'ERROR'])
            }
        
        return user_stats
    
    def analyze_compliance_metrics(self) -> Dict:
        """Analyze compliance-related metrics including failed attempts, deletions, and access patterns."""
        # Initialize counters
        metrics = {
            'failed_operations': {
                'total': 0,
                'by_user': defaultdict(int),
                'by_ip': defaultdict(int),
                'by_error_type': defaultdict(int)
            },
            'delete_operations': {
                'total': 0,
                'by_user': defaultdict(int),
                'by_ip': defaultdict(int),
                'failed': 0,
                'successful': 0
            },
            'access_patterns': {
                'unique_ips': set(),
                'unique_users': set(),
                'ip_user_mappings': defaultdict(set),
                'user_ip_mappings': defaultdict(set)
            },
            'suspicious_activity': []
        }
        
        # Analyze each log entry
        for entry in self.log_entries:
            # Track unique IPs and users
            if entry['ip_address']:
                metrics['access_patterns']['unique_ips'].add(entry['ip_address'])
            if entry['user']:
                metrics['access_patterns']['unique_users'].add(entry['user'])
            
            # Map IPs to users and vice versa
            if entry['ip_address'] and entry['user']:
                metrics['access_patterns']['ip_user_mappings'][entry['ip_address']].add(entry['user'])
                metrics['access_patterns']['user_ip_mappings'][entry['user']].add(entry['ip_address'])
            
            # Analyze failed operations
            if entry['message_type'] == 'ERROR':
                metrics['failed_operations']['total'] += 1
                metrics['failed_operations']['by_user'][entry['user']] += 1
                if entry['ip_address']:
                    metrics['failed_operations']['by_ip'][entry['ip_address']] += 1
                metrics['failed_operations']['by_error_type'][entry['error_code']] += 1
            
            # Analyze delete operations
            if entry['query'] and 'DELETE' in entry['query'].upper():
                metrics['delete_operations']['total'] += 1
                metrics['delete_operations']['by_user'][entry['user']] += 1
                if entry['ip_address']:
                    metrics['delete_operations']['by_ip'][entry['ip_address']] += 1
                
                if entry['message_type'] == 'ERROR':
                    metrics['delete_operations']['failed'] += 1
                else:
                    metrics['delete_operations']['successful'] += 1

        # Convert sets to lists for JSON serialization
        metrics['access_patterns']['unique_ips'] = list(metrics['access_patterns']['unique_ips'])
        metrics['access_patterns']['unique_users'] = list(metrics['access_patterns']['unique_users'])
        metrics['access_patterns']['ip_user_mappings'] = {
            k: list(v) for k, v in metrics['access_patterns']['ip_user_mappings'].items()
        }
        metrics['access_patterns']['user_ip_mappings'] = {
            k: list(v) for k, v in metrics['access_patterns']['user_ip_mappings'].items()
        }
        
        return metrics

    def generate_compliance_report(self) -> Dict:
        """Generate a comprehensive compliance report."""
        compliance_metrics = self.analyze_compliance_metrics()
        sensitive_data_analysis = self.analyze_sensitive_data_operations()
        error_analysis = self.analyze_error_patterns()
        user_analysis = self.analyze_user_activity()
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'analysis_period': {
                'start': min(entry['timestamp'] for entry in self.log_entries).isoformat(),
                'end': max(entry['timestamp'] for entry in self.log_entries).isoformat()
            },
            'summary': {
                'total_operations': len(self.log_entries),
                'failed_operations': compliance_metrics['failed_operations']['total'],
                'delete_operations': compliance_metrics['delete_operations']['total'],
                'unique_users': len(compliance_metrics['access_patterns']['unique_users']),
                'unique_ips': len(compliance_metrics['access_patterns']['unique_ips'])
            },
            'access_patterns': {
                'user_analysis': user_analysis,
                'user_activity': {
                    user: {
                        'total_failed_operations': compliance_metrics['failed_operations']['by_user'][user],
                        'total_delete_operations': compliance_metrics['delete_operations']['by_user'][user],
                        'accessed_from_ips': compliance_metrics['access_patterns']['user_ip_mappings'][user]
                    }
                    for user in compliance_metrics['access_patterns']['unique_users']
                },
                'ip_activity': {
                    ip: {
                        'total_failed_operations': compliance_metrics['failed_operations']['by_ip'][ip],
                        'total_delete_operations': compliance_metrics['delete_operations']['by_ip'][ip],
                        'users': compliance_metrics['access_patterns']['ip_user_mappings'][ip]
                    }
                    for ip in compliance_metrics['access_patterns']['unique_ips']
                }
            },
            'sensitive_data_operations': sensitive_data_analysis,
            'compliance_alerts': self._generate_compliance_alerts(compliance_metrics),
            'error_analysis': error_analysis,
            
        }
        
        return report

    def _generate_compliance_alerts(self, metrics: Dict) -> List[Dict]:
        """Generate compliance alerts based on analyzed metrics."""
        alerts = []
        
        # Alert on high number of failed operations from same IP
        for ip, count in metrics['failed_operations']['by_ip'].items():
            if count >= 5:  # Threshold for suspicious activity
                alerts.append({
                    'severity': 'HIGH',
                    'type': 'Failed Operations',
                    'description': f'High number of failed operations ({count}) from IP {ip}',
                    'recommendation': 'Investigate potential unauthorized access attempts'
                })
        
        # Alert on users accessing from multiple IPs
        for user, ips in metrics['access_patterns']['user_ip_mappings'].items():
            if len(ips) > 3:  # Threshold for multiple IP access
                alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'Multiple IP Access',
                    'description': f'User {user} accessed from {len(ips)} different IPs',
                    'recommendation': 'Verify if multiple IP access is authorized'
                })
        
        # Alert on high number of delete operations
        for user, count in metrics['delete_operations']['by_user'].items():
            if count > 5:  # Threshold for delete operations
                alerts.append({
                    'severity': 'MEDIUM',
                    'type': 'Delete Operations',
                    'description': f'High number of delete operations ({count}) by user {user}',
                    'recommendation': 'Review delete operation patterns'
                })
        
        return alerts
    
    def print_unique_commands(self):
        """Print a table of unique sets of commands made by users."""
        command_data = []

        for entry in self.log_entries:
            print(entry)
            if entry['query']:
                command_data.append({
                    'user': entry['user'],
                    'command': entry['query']
                })

        # Remove duplicates by converting to a set of tuples
        unique_commands = {(item['user'], item['command']) for item in command_data}

        # Convert back to a list of dictionaries for DataFrame
        unique_commands_list = [{'user': user, 'command': command} for user, command in unique_commands]

        # Create a pandas DataFrame to format the output
        df = pd.DataFrame(unique_commands_list)
        print("\nUnique Commands by Users:")
        print(df.to_string(index=False))

def main(log_file_path: str):
    """Main function to run the compliance analysis."""
    # Read the log file
    with open(log_file_path, 'r') as f:
        log_data = f.read()
    
    # Create analyzer instance
    analyzer = PostgresAuditAnalyzer(log_data)
    
    # Generate compliance report
    report = analyzer.generate_compliance_report()

    analyzer.print_unique_commands()
    
    # Save report to file
    report_filename = f'compliance_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nCompliance Analysis Report generated: {report_filename}")
    
    # Print key compliance metrics
    print("\nKey Compliance Metrics:")
    print(f"Analysis Period: {report['analysis_period']['start']} to {report['analysis_period']['end']}")
    print(f"Total Operations: {report['summary']['total_operations']}")
    print(f"Failed Operations: {report['summary']['failed_operations']}")
    print(f"Delete Operations: {report['summary']['delete_operations']}")
    print(f"Unique Users: {report['summary']['unique_users']}")
    print(f"Unique IPs: {report['summary']['unique_ips']}")
    
    if report['compliance_alerts']:
        print("\nCompliance Alerts:")
        for alert in report['compliance_alerts']:
            print(f"\n[{alert['severity']}] {alert['type']}")
            print(f"Description: {alert['description']}")
            print(f"Recommendation: {alert['recommendation']}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python script.py <log_file_path>")
        sys.exit(1)
    main(sys.argv[1])