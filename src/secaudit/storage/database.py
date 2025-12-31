"""
Database storage implementation for SecAudit
"""
import sqlite3
import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from ..base_storage import BaseStorage


class Database(BaseStorage):
    """SQLite database implementation for SecAudit"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.db_path = config.get('path', './data/secaudit.db')
        self.backup_interval = config.get('backup_interval', '1h')
        self.retention_days = config.get('retention_days', 30)
        self.connection = None
    
    def connect(self) -> bool:
        """Establish connection to SQLite database"""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  # Enable dict-like access
            self._create_tables()
            self.logger.info(f"Connected to database: {self.db_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            return False
    
    def disconnect(self) -> bool:
        """Close database connection"""
        try:
            if self.connection:
                self.connection.close()
                self.connection = None
                self.logger.info("Database connection closed")
                return True
        except Exception as e:
            self.logger.error(f"Error closing database connection: {e}")
            return False
        return True
    
    def _create_tables(self) -> None:
        """Create necessary database tables"""
        cursor = self.connection.cursor()
        
        # Log entries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                hostname TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                source_ip TEXT,
                username TEXT,
                target_user TEXT,
                port INTEGER,
                command TEXT,
                raw_line TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Threat alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                confidence REAL NOT NULL,
                timestamp TEXT NOT NULL,
                affected_assets TEXT,
                evidence TEXT,
                mitigation TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Analysis results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_entries INTEGER NOT NULL,
                parsed_entries INTEGER NOT NULL,
                threats_detected INTEGER NOT NULL,
                anomalies TEXT,
                processing_time REAL NOT NULL,
                start_time TEXT,
                end_time TEXT,
                metadata TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Cache table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expires_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        self.connection.commit()
    
    def save(self, key: str, data: Any) -> bool:
        """Save data to database"""
        try:
            if key.startswith('log_entry:'):
                return self._save_log_entry(data)
            elif key.startswith('threat_alert:'):
                return self._save_threat_alert(data)
            elif key.startswith('analysis_result:'):
                return self._save_analysis_result(data)
            else:
                self.logger.warning(f"Unknown data type for key: {key}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to save data: {e}")
            return False
    
    def _save_log_entry(self, log_entry: Dict[str, Any]) -> bool:
        """Save log entry to database"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO log_entries (
                timestamp, hostname, event_type, severity, source_ip,
                username, target_user, port, command, raw_line, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            log_entry.get('timestamp'),
            log_entry.get('hostname'),
            log_entry.get('event_type'),
            log_entry.get('severity'),
            log_entry.get('source_ip'),
            log_entry.get('username'),
            log_entry.get('target_user'),
            log_entry.get('port'),
            log_entry.get('command'),
            log_entry.get('raw_line'),
            json.dumps(log_entry.get('metadata', {}))
        ))
        self.connection.commit()
        return True
    
    def _save_threat_alert(self, threat_alert: Dict[str, Any]) -> bool:
        """Save threat alert to database"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO threat_alerts (
                rule_id, rule_name, severity, description, confidence,
                timestamp, affected_assets, evidence, mitigation
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat_alert.get('rule_id'),
            threat_alert.get('rule_name'),
            threat_alert.get('severity'),
            threat_alert.get('description'),
            threat_alert.get('confidence'),
            threat_alert.get('timestamp'),
            json.dumps(threat_alert.get('affected_assets', [])),
            json.dumps(threat_alert.get('evidence', [])),
            threat_alert.get('mitigation')
        ))
        self.connection.commit()
        return True
    
    def _save_analysis_result(self, result: Dict[str, Any]) -> bool:
        """Save analysis result to database"""
        cursor = self.connection.cursor()
        cursor.execute('''
            INSERT INTO analysis_results (
                total_entries, parsed_entries, threats_detected,
                anomalies, processing_time, start_time, end_time, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            result.get('total_entries', 0),
            result.get('parsed_entries', 0),
            result.get('threats_detected', 0),
            json.dumps(result.get('anomalies', [])),
            result.get('processing_time', 0.0),
            result.get('start_time'),
            result.get('end_time'),
            json.dumps(result.get('metadata', {}))
        ))
        self.connection.commit()
        return True
    
    def load(self, key: str) -> Optional[Any]:
        """Load data from database"""
        try:
            if key.startswith('log_entry:'):
                return self._load_log_entry(key)
            elif key.startswith('threat_alert:'):
                return self._load_threat_alert(key)
            elif key.startswith('analysis_result:'):
                return self._load_analysis_result(key)
            else:
                self.logger.warning(f"Unknown data type for key: {key}")
                return None
        except Exception as e:
            self.logger.error(f"Failed to load data: {e}")
            return None
    
    def _load_log_entry(self, key: str) -> Optional[Dict[str, Any]]:
        """Load log entry from database"""
        entry_id = key.replace('log_entry:', '')
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM log_entries WHERE id = ?', (entry_id,))
        row = cursor.fetchone()
        
        if row:
            return dict(row)
        return None
    
    def _load_threat_alert(self, key: str) -> Optional[Dict[str, Any]]:
        """Load threat alert from database"""
        alert_id = key.replace('threat_alert:', '')
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM threat_alerts WHERE id = ?', (alert_id,))
        row = cursor.fetchone()
        
        if row:
            result = dict(row)
            result['affected_assets'] = json.loads(result.get('affected_assets', '[]'))
            result['evidence'] = json.loads(result.get('evidence', '[]'))
            return result
        return None
    
    def _load_analysis_result(self, key: str) -> Optional[Dict[str, Any]]:
        """Load analysis result from database"""
        result_id = key.replace('analysis_result:', '')
        cursor = self.connection.cursor()
        cursor.execute('SELECT * FROM analysis_results WHERE id = ?', (result_id,))
        row = cursor.fetchone()
        
        if row:
            result = dict(row)
            result['anomalies'] = json.loads(result.get('anomalies', '[]'))
            result['metadata'] = json.loads(result.get('metadata', '{}'))
            return result
        return None
    
    def delete(self, key: str) -> bool:
        """Delete data from database"""
        try:
            if key.startswith('log_entry:'):
                entry_id = key.replace('log_entry:', '')
                cursor = self.connection.cursor()
                cursor.execute('DELETE FROM log_entries WHERE id = ?', (entry_id,))
            elif key.startswith('threat_alert:'):
                alert_id = key.replace('threat_alert:', '')
                cursor = self.connection.cursor()
                cursor.execute('DELETE FROM threat_alerts WHERE id = ?', (alert_id,))
            elif key.startswith('analysis_result:'):
                result_id = key.replace('analysis_result:', '')
                cursor = self.connection.cursor()
                cursor.execute('DELETE FROM analysis_results WHERE id = ?', (result_id,))
            else:
                self.logger.warning(f"Unknown data type for key: {key}")
                return False
            
            self.connection.commit()
            return True
        except Exception as e:
            self.logger.error(f"Failed to delete data: {e}")
            return False
    
    def list_keys(self, pattern: Optional[str] = None) -> List[str]:
        """List all keys in database"""
        keys = []
        
        try:
            cursor = self.connection.cursor()
            
            if pattern and pattern.startswith('log_entry'):
                cursor.execute('SELECT id FROM log_entries')
                keys.extend([f"log_entry:{row[0]}" for row in cursor.fetchall()])
            elif pattern and pattern.startswith('threat_alert'):
                cursor.execute('SELECT id FROM threat_alerts')
                keys.extend([f"threat_alert:{row[0]}" for row in cursor.fetchall()])
            elif pattern and pattern.startswith('analysis_result'):
                cursor.execute('SELECT id FROM analysis_results')
                keys.extend([f"analysis_result:{row[0]}" for row in cursor.fetchall()])
            else:
                # List all keys
                cursor.execute('SELECT id FROM log_entries')
                keys.extend([f"log_entry:{row[0]}" for row in cursor.fetchall()])
                cursor.execute('SELECT id FROM threat_alerts')
                keys.extend([f"threat_alert:{row[0]}" for row in cursor.fetchall()])
                cursor.execute('SELECT id FROM analysis_results')
                keys.extend([f"analysis_result:{row[0]}" for row in cursor.fetchall()])
            
            return keys
        except Exception as e:
            self.logger.error(f"Failed to list keys: {e}")
            return []
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check on database"""
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT COUNT(*) FROM log_entries')
            log_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM threat_alerts')
            alert_count = cursor.fetchone()[0]
            
            return {
                'status': 'healthy',
                'connection': True,
                'error': None,
                'log_entries': log_count,
                'threat_alerts': alert_count,
                'database_path': self.db_path
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'connection': False,
                'error': str(e),
                'log_entries': 0,
                'threat_alerts': 0,
                'database_path': self.db_path
            }
    
    def cleanup_old_data(self) -> bool:
        """Clean up old data based on retention policy"""
        try:
            cutoff_date = datetime.now() - timedelta(days=self.retention_days)
            cutoff_str = cutoff_date.isoformat()
            
            cursor = self.connection.cursor()
            
            # Delete old log entries
            cursor.execute('DELETE FROM log_entries WHERE created_at < ?', (cutoff_str,))
            log_deleted = cursor.rowcount
            
            # Delete old threat alerts
            cursor.execute('DELETE FROM threat_alerts WHERE created_at < ?', (cutoff_str,))
            alert_deleted = cursor.rowcount
            
            # Delete old analysis results
            cursor.execute('DELETE FROM analysis_results WHERE created_at < ?', (cutoff_str,))
            result_deleted = cursor.rowcount
            
            self.connection.commit()
            
            self.logger.info(f"Cleaned up {log_deleted} log entries, {alert_deleted} threat alerts, {result_deleted} analysis results")
            return True
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
            return False