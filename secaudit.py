import sys
import os
import json
from collections import defaultdict, Counter
from parser.log_parser import LogParser

class SecAudit:
    """Main Security Audit CLI application"""
    
    def __init__(self):
        self.parser = LogParser()
        self.logs = []
    
    def read_log_file(self, filepath: str) -> bool:
        """
        Read and parse a log file.
        
        Args:
            filepath (str): Path to the log file
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            print(f"📁 Reading log file: {filepath}")
            print(f"📊 Total lines: {len(lines)}")
            print("-" * 60)
            
            parsed_count = 0
            for line_num, line in enumerate(lines, 1):
                parsed_log = self.parser.parse_line(line)
                if parsed_log:
                    parsed_log['line_number'] = line_num
                    self.logs.append(parsed_log)
                    parsed_count += 1
            
            print(f"✅ Successfully parsed {parsed_count} log entries")
            return True
            
        except FileNotFoundError:
            print(f"❌ Error: File '{filepath}' not found")
            return False
        except Exception as e:
            print(f"❌ Error reading file: {e}")
            return False
    
    def print_logs(self, limit: int = None):
        """Print parsed logs in a readable format"""
        if not self.logs:
            print("No logs to display")
            return
        
        logs_to_show = self.logs[:limit] if limit else self.logs
        
        print(f"\n🔍 PARSED LOG ENTRIES ({len(logs_to_show)} shown)")
        print("=" * 80)
        
        for i, log in enumerate(logs_to_show, 1):
            print(f"\n[{i}] Line {log.get('line_number', 'N/A')} - {log['event_type']} ({log['severity']})")
            print(f"    Timestamp: {log.get('timestamp', 'N/A')}")
            
            if 'username' in log:
                print(f"    Username:  {log['username']}")
            if 'ip_address' in log:
                print(f"    IP:        {log['ip_address']}")
            if 'port' in log:
                print(f"    Port:      {log['port']}")
            if 'command' in log:
                print(f"    Command:   {log['command']}")
            
            print(f"    Raw:       {log['raw_line'][:80]}{'...' if len(log['raw_line']) > 80 else ''}")
    
    def generate_summary(self):
        """Generate security summary statistics"""
        if not self.logs:
            print("No logs to analyze")
            return
        
        print(f"\n📈 SECURITY SUMMARY")
        print("=" * 50)
        
        # Event type distribution
        event_counts = Counter(log['event_type'] for log in self.logs)
        print(f"\n🔸 Event Types:")
        for event_type, count in event_counts.most_common():
            print(f"    {event_type:<20} {count:>3}")
        
        # Severity distribution
        severity_counts = Counter(log['severity'] for log in self.logs)
        print(f"\n🚨 Severity Levels:")
        for severity, count in severity_counts.most_common():
            print(f"    {severity:<10} {count:>3}")
        
        # Top IPs
        ip_counts = Counter(log['ip_address'] for log in self.logs if 'ip_address' in log)
        if ip_counts:
            print(f"\n🌐 IP Addresses:")
            for ip, count in ip_counts.most_common(10):
                print(f"    {ip:<15} {count:>3}")
        
        # Failed login attempts
        failed_logins = [log for log in self.logs if log['event_type'] == 'SSH_FAILED_PASSWORD']
        if failed_logins:
            failed_users = Counter(log['username'] for log in failed_logins)
            print(f"\n🔐 Failed Login Attempts by User:")
            for user, count in failed_users.most_common(10):
                print(f"    {user:<15} {count:>3}")
    
    def export_json(self, filepath: str):
        """Export parsed logs to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.logs, f, indent=2)
            print(f"📤 Exported {len(self.logs)} logs to {filepath}")
        except Exception as e:
            print(f"❌ Error exporting to JSON: {e}")

def main():
    """Main CLI entry point"""
    print("🛡️  SecAudit - Security Log Analyzer")
    print("=" * 40)
    
    if len(sys.argv) < 2:
        print("Usage: python secaudit.py <log_file_path> [options]")
        print("\nOptions:")
        print("  --limit N     Show only first N entries")
        print("  --json FILE   Export results to JSON file")
        print("  --summary     Show security summary only")
        return
    
    log_file = sys.argv[1]
    
    # Parse command line options
    show_limit = None
    export_json = None
    summary_only = False
    
    for i, arg in enumerate(sys.argv[2:], 2):
        if arg == '--limit' and i + 1 < len(sys.argv):
            try:
                show_limit = int(sys.argv[i + 1])
            except ValueError:
                print("❌ Invalid limit value")
                return
        elif arg == '--json' and i + 1 < len(sys.argv):
            export_json = sys.argv[i + 1]
        elif arg == '--summary':
            summary_only = True
    
    # Initialize and run SecAudit
    auditor = SecAudit()
    
    if not auditor.read_log_file(log_file):
        return
    
    if not summary_only:
        auditor.print_logs(limit=show_limit)
    
    auditor.generate_summary()
    
    if export_json:
        auditor.export_json(export_json)

if __name__ == "__main__":
    main()