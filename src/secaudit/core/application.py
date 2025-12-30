"""
Main application orchestrator for SecAudit
"""
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from .config import ConfigManager
from .plugin_manager import PluginManager
from ..models.analysis_result import AnalysisResult

class SecAuditApplication:
    """Main SecAudit application orchestrator"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the SecAudit application
        
        Args:
            config_path (str, optional): Path to configuration file
        """
        self.config = ConfigManager(config_path)
        self.logger = self._setup_logging()
        self.plugin_manager = PluginManager(self.config)
        
        # Initialize components
        self.input_handler = None
        self.parser = None
        self.analyzer = None
        self.output_handler = None
        
        self.logger.info("SecAudit application initialized")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        log_level = self.config.get('secaudit.log_level', 'INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        return logging.getLogger(__name__)
    
    def load_components(self) -> bool:
        """Load and initialize all application components"""
        try:
            # Load plugins
            self.plugin_manager.load_plugins()
            
            # Initialize input handler
            from ..input import FileInput, StreamInput, APIInput
            input_type = self.config.get('input.type', 'file')
            
            if input_type == 'file':
                self.input_handler = FileInput(self.config.get('input', {}))
            elif input_type == 'stream':
                self.input_handler = StreamInput(self.config.get('input', {}))
            elif input_type == 'api':
                self.input_handler = APIInput(self.config.get('input', {}))
            else:
                raise ValueError(f"Unknown input type: {input_type}")
            
            # Initialize parser
            from ..parsers import SSHParser, SyslogParser
            parser_type = self.config.get('input.format', 'ssh')
            
            if parser_type == 'ssh':
                self.parser = SSHParser()
            elif parser_type == 'syslog':
                self.parser = SyslogParser()
            else:
                raise ValueError(f"Unknown parser type: {parser_type}")
            
            # Initialize analyzer
            from ..analysis import ThreatDetector, AnomalyDetector
            self.analyzer = ThreatDetector(self.config.get('analysis', {}))
            self.anomaly_detector = AnomalyDetector(self.config.get('analysis', {}))
            
            # Initialize output handler
            from ..output import JSONExporter, HTMLReporter
            output_format = self.config.get('output.format', 'json')
            
            if output_format == 'json':
                self.output_handler = JSONExporter(self.config.get('output', {}))
            elif output_format == 'html':
                self.output_handler = HTMLReporter(self.config.get('output', {}))
            else:
                raise ValueError(f"Unknown output format: {output_format}")
            
            self.logger.info("All components loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load components: {e}")
            return False
    
    def run_analysis(self, input_path: str) -> AnalysisResult:
        """
        Run complete analysis on input data
        
        Args:
            input_path (str): Path to input file or stream identifier
            
        Returns:
            AnalysisResult: Complete analysis results
        """
        start_time = datetime.now()
        
        try:
            self.logger.info(f"Starting analysis on: {input_path}")
            
            # Read input
            raw_data = self.input_handler.read(input_path)
            self.logger.info(f"Read {len(raw_data)} lines from input")
            
            # Parse logs
            parsed_logs = []
            for line in raw_data:
                parsed = self.parser.parse(line)
                if parsed:
                    parsed_logs.append(parsed)
            
            self.logger.info(f"Parsed {len(parsed_logs)} valid log entries")
            
            # Analyze logs
            threats = self.analyzer.detect_threats(parsed_logs)
            anomalies = self.anomaly_detector.detect_anomalies(parsed_logs)
            
            # Generate results
            processing_time = (datetime.now() - start_time).total_seconds()
            
            results = AnalysisResult(
                total_entries=len(raw_data),
                parsed_entries=len(parsed_logs),
                threats_detected=threats,
                anomalies=anomalies,
                processing_time=processing_time
            )
            
            # Export results
            self.output_handler.export(results)
            
            self.logger.info("Analysis completed successfully")
            return results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise
    
    def run_interactive(self) -> None:
        """Run application in interactive mode"""
        print("🛡️  SecAudit - Interactive Mode")
        print("=" * 40)
        
        while True:
            try:
                command = input("\nsecaudit> ").strip().lower()
                
                if command == 'quit' or command == 'exit':
                    print("Goodbye!")
                    break
                elif command == 'help':
                    self._show_help()
                elif command.startswith('analyze '):
                    file_path = command[8:].strip()
                    if file_path:
                        results = self.run_analysis(file_path)
                        print(f"\n✅ Analysis complete!")
                        print(f"📊 Total entries: {results.total_entries}")
                        print(f"✅ Parsed entries: {results.parsed_entries}")
                        print(f"🚨 Threats detected: {len(results.threats_detected)}")
                        print(f"🔍 Anomalies found: {len(results.anomalies)}")
                        print(f"⏱️  Processing time: {results.processing_time:.2f} seconds")
                    else:
                        print("❌ Please specify a file path")
                elif command == 'status':
                    self._show_status()
                else:
                    print("❌ Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
    
    def _show_help(self) -> None:
        """Show help information"""
        help_text = """
Available commands:
  analyze <file_path>    - Analyze a log file
  status                 - Show current configuration status
  help                   - Show this help message
  quit/exit              - Exit interactive mode
        """
        print(help_text)
    
    def _show_status(self) -> None:
        """Show current application status"""
        print("\n📋 Application Status:")
        print(f"   Configuration: {self.config.config_path or 'Default'}")
        print(f"   Input Type: {self.config.get('input.type', 'file')}")
        print(f"   Parser: {self.config.get('input.format', 'ssh')}")
        print(f"   Output Format: {self.config.get('output.format', 'json')}")
        print(f"   Plugins Loaded: {len(self.plugin_manager.plugins)}")
        print(f"   Log Level: {self.config.get('secaudit.log_level', 'INFO')}")