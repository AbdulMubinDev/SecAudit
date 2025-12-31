"""
Cloud service log parser for SecAudit
"""
import json
import re
from typing import Any, Dict, Optional, List
from datetime import datetime
from ..base_parser import BaseParser


class CloudParser(BaseParser):
    """Cloud service log parser implementation"""
    
    def __init__(self):
        super().__init__()
        self.cloud_providers = {
            'aws': self._parse_aws_log,
            'azure': self._parse_azure_log,
            'gcp': self._parse_gcp_log,
            'generic': self._parse_generic_cloud_log
        }
        
        # AWS CloudTrail patterns
        self.aws_patterns = {
            'signin': re.compile(r'(?P<event_name>ConsoleLogin|AssumeRole)'),
            'iam': re.compile(r'(?P<event_name>CreateUser|DeleteUser|AttachUserPolicy)'),
            'ec2': re.compile(r'(?P<event_name>RunInstances|StopInstances|TerminateInstances)'),
            's3': re.compile(r'(?P<event_name>PutObject|GetObject|DeleteObject)')
        }
        
        # Azure patterns
        self.azure_patterns = {
            'signin': re.compile(r'(?P<operation_name>Sign-in|Token Issuance)'),
            'iam': re.compile(r'(?P<operation_name>Create User|Delete User|Add member to role)'),
            'compute': re.compile(r'(?P<operation_name>Virtual Machine Create|Virtual Machine Delete)')
        }
        
        # GCP patterns
        self.gcp_patterns = {
            'iam': re.compile(r'(?P<event_type>admin.googleapis.com|iam.googleapis.com)'),
            'compute': re.compile(r'(?P<event_type>compute.googleapis.com)'),
            'storage': re.compile(r'(?P<event_type>storage.googleapis.com)')
        }
    
    def can_parse(self, line: str) -> bool:
        """Check if this parser can handle the given line"""
        # Check for cloud-specific indicators
        cloud_indicators = [
            r'CloudTrail',           # AWS
            r'AzureAD',              # Azure
            r'audit\.log',           # GCP
            r'aws:',                  # AWS ARN prefix
            r'/subscriptions/',      # Azure subscription
            r'projects/',            # GCP project
            r'eventTime',            # Common cloud timestamp field
            r'requestId',            # Common cloud request ID
        ]
        
        for indicator in cloud_indicators:
            if re.search(indicator, line, re.IGNORECASE):
                return True
        
        # Check for JSON format (common in cloud logs)
        try:
            json.loads(line.strip())
            return True
        except (json.JSONDecodeError, ValueError):
            pass
        
        return False
    
    def parse(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse a cloud service log line"""
        if not line or not line.strip():
            return None
        
        try:
            # Try to parse as JSON first (most cloud logs are JSON)
            try:
                log_data = json.loads(line.strip())
                return self._parse_cloud_json(log_data)
            except json.JSONDecodeError:
                pass
            
            # Try provider-specific parsing
            for provider, parser_func in self.cloud_providers.items():
                result = parser_func(line)
                if result:
                    result['cloud_provider'] = provider
                    return result
            
            # Try generic cloud parsing
            return self._parse_generic_cloud_log(line)
            
        except Exception as e:
            self.logger.warning(f"Failed to parse cloud log: {e}")
            return None
    
    def _parse_cloud_json(self, log_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse cloud log in JSON format"""
        try:
            # Determine cloud provider
            provider = self._detect_cloud_provider(log_data)
            
            # Extract common fields
            timestamp = self._extract_timestamp(log_data)
            event_type = self._extract_event_type(log_data, provider)
            severity = self._extract_severity(log_data, provider)
            
            # Extract provider-specific fields
            provider_fields = self._extract_provider_fields(log_data, provider)
            
            result = {
                'timestamp': timestamp,
                'event_type': event_type,
                'severity': severity,
                'cloud_provider': provider,
                'cloud_service': provider_fields.get('service'),
                'cloud_resource': provider_fields.get('resource'),
                'cloud_operation': provider_fields.get('operation'),
                'cloud_user': provider_fields.get('user'),
                'cloud_source_ip': provider_fields.get('source_ip'),
                'cloud_request_id': provider_fields.get('request_id'),
                'raw_line': json.dumps(log_data),
                'format': 'json'
            }
            
            # Sanitize fields
            for key, value in result.items():
                if isinstance(value, str):
                    result[key] = self.sanitize_field(value)
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Failed to parse cloud JSON log: {e}")
            return None
    
    def _detect_cloud_provider(self, log_data: Dict[str, Any]) -> str:
        """Detect cloud provider from log data"""
        # Check for AWS indicators
        if 'awsRegion' in log_data or 'eventSource' in log_data:
            return 'aws'
        
        # Check for Azure indicators
        if 'operationName' in log_data or 'callerIpAddress' in log_data:
            return 'azure'
        
        # Check for GCP indicators
        if 'protoPayload' in log_data or 'resource' in log_data:
            return 'gcp'
        
        # Check for common fields
        if 'eventTime' in log_data:
            # Try to determine from service name
            service = log_data.get('serviceName', '').lower()
            if 'aws' in service:
                return 'aws'
            elif 'azure' in service or 'microsoft' in service:
                return 'azure'
            elif 'gcp' in service or 'google' in service:
                return 'gcp'
        
        return 'generic'
    
    def _extract_timestamp(self, log_data: Dict[str, Any]) -> Optional[datetime]:
        """Extract timestamp from cloud log"""
        timestamp_fields = ['eventTime', 'timestamp', 'time', '@timestamp']
        
        for field in timestamp_fields:
            if field in log_data:
                return self.parse_timestamp(str(log_data[field]))
        
        return None
    
    def _extract_event_type(self, log_data: Dict[str, Any], provider: str) -> str:
        """Extract event type from cloud log"""
        if provider == 'aws':
            event_name = log_data.get('eventName', '')
            return f"AWS_{event_name.upper()}"
        elif provider == 'azure':
            operation_name = log_data.get('operationName', '')
            return f"AZURE_{operation_name.replace(' ', '_').upper()}"
        elif provider == 'gcp':
            service_name = log_data.get('serviceName', '')
            method_name = log_data.get('methodName', '')
            return f"GCP_{service_name.replace('.', '_').upper()}_{method_name.upper()}"
        else:
            return "CLOUD_GENERIC_EVENT"
    
    def _extract_severity(self, log_data: Dict[str, Any], provider: str) -> str:
        """Extract severity from cloud log"""
        # Check for explicit severity
        severity_fields = ['severity', 'level', 'logLevel']
        for field in severity_fields:
            if field in log_data:
                severity = str(log_data[field]).upper()
                if severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    return severity
        
        # Determine from event type
        event_type = self._extract_event_type(log_data, provider)
        critical_events = ['AWS_CONSOLELOGIN', 'AZURE_SIGN_IN', 'GCP_IAM_POLICY']
        
        if any(event in event_type for event in critical_events):
            return 'HIGH'
        
        return 'MEDIUM'
    
    def _extract_provider_fields(self, log_data: Dict[str, Any], provider: str) -> Dict[str, Any]:
        """Extract provider-specific fields"""
        if provider == 'aws':
            return self._extract_aws_fields(log_data)
        elif provider == 'azure':
            return self._extract_azure_fields(log_data)
        elif provider == 'gcp':
            return self._extract_gcp_fields(log_data)
        else:
            return self._extract_generic_fields(log_data)
    
    def _extract_aws_fields(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract AWS-specific fields"""
        return {
            'service': log_data.get('eventSource', '').replace('.amazonaws.com', ''),
            'resource': log_data.get('resources', [{}])[0].get('ARN') if log_data.get('resources') else None,
            'operation': log_data.get('eventName'),
            'user': log_data.get('userIdentity', {}).get('arn'),
            'source_ip': log_data.get('sourceIPAddress'),
            'request_id': log_data.get('requestID')
        }
    
    def _extract_azure_fields(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Azure-specific fields"""
        return {
            'service': log_data.get('resourceType'),
            'resource': log_data.get('resourceId'),
            'operation': log_data.get('operationName'),
            'user': log_data.get('callerIpAddress'),
            'source_ip': log_data.get('callerIpAddress'),
            'request_id': log_data.get('correlationId')
        }
    
    def _extract_gcp_fields(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract GCP-specific fields"""
        proto_payload = log_data.get('protoPayload', {})
        return {
            'service': log_data.get('serviceName'),
            'resource': proto_payload.get('resourceName'),
            'operation': proto_payload.get('methodName'),
            'user': proto_payload.get('authenticationInfo', {}).get('principalEmail'),
            'source_ip': proto_payload.get('requestMetadata', {}).get('callerIp'),
            'request_id': proto_payload.get('requestId')
        }
    
    def _extract_generic_fields(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract generic cloud fields"""
        return {
            'service': log_data.get('service'),
            'resource': log_data.get('resource'),
            'operation': log_data.get('operation'),
            'user': log_data.get('user'),
            'source_ip': log_data.get('source_ip'),
            'request_id': log_data.get('request_id')
        }
    
    def _parse_aws_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse AWS CloudTrail log"""
        # This would implement specific AWS log parsing
        # For now, return None to use JSON parsing
        return None
    
    def _parse_azure_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse Azure Activity log"""
        # This would implement specific Azure log parsing
        # For now, return None to use JSON parsing
        return None
    
    def _parse_gcp_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse GCP Audit log"""
        # This would implement specific GCP log parsing
        # For now, return None to use JSON parsing
        return None
    
    def _parse_generic_cloud_log(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse generic cloud log format"""
        try:
            # Extract common cloud log patterns
            timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)', line)
            timestamp = None
            if timestamp_match:
                timestamp = self.parse_timestamp(timestamp_match.group(1))
            
            # Extract service name
            service_match = re.search(r'service[=:]\s*([^\s,]+)', line, re.IGNORECASE)
            service = service_match.group(1) if service_match else None
            
            # Extract operation
            operation_match = re.search(r'operation[=:]\s*([^\s,]+)', line, re.IGNORECASE)
            operation = operation_match.group(1) if operation_match else None
            
            # Extract user
            user_match = re.search(r'user[=:]\s*([^\s,]+)', line, re.IGNORECASE)
            user = user_match.group(1) if user_match else None
            
            # Extract source IP
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            source_ip = ip_match.group(1) if ip_match else None
            
            result = {
                'timestamp': timestamp,
                'event_type': 'CLOUD_GENERIC_EVENT',
                'severity': 'MEDIUM',
                'cloud_provider': 'generic',
                'cloud_service': service,
                'cloud_operation': operation,
                'cloud_user': user,
                'cloud_source_ip': source_ip,
                'raw_line': line.strip(),
                'format': 'generic'
            }
            
            # Sanitize fields
            for key, value in result.items():
                if isinstance(value, str):
                    result[key] = self.sanitize_field(value)
            
            return result
            
        except Exception as e:
            self.logger.warning(f"Failed to parse generic cloud log: {e}")
            return None
    
    def get_supported_providers(self) -> List[str]:
        """Get list of supported cloud providers"""
        return list(self.cloud_providers.keys())
    
    def validate_cloud_log(self, log_data: Dict[str, Any]) -> bool:
        """Validate parsed cloud log data"""
        required_fields = ['timestamp', 'event_type', 'severity', 'cloud_provider']
        
        for field in required_fields:
            if field not in log_data or log_data[field] is None:
                return False
        
        # Validate timestamp
        if not isinstance(log_data['timestamp'], datetime):
            return False
        
        # Validate cloud provider
        supported_providers = self.get_supported_providers()
        if log_data['cloud_provider'] not in supported_providers:
            return False
        
        return True