"""
Simple HTML report exporter for SecAudit (minimal)
"""
import os
from typing import Dict, Any
from .base_output import BaseOutput

class HTMLReporter(BaseOutput):
    """Minimal HTML reporter implementation"""

    def export(self, results: Dict[str, Any]) -> bool:
        try:
            if not self.validate_output_path():
                return False

            filename = self.generate_filename('secaudit_report')
            filepath = os.path.join(self.output_path, f"{filename}.html")

            # Accept AnalysisResult-like objects
            if hasattr(results, 'to_dict') and callable(getattr(results, 'to_dict')):
                data = results.to_dict()
            else:
                data = results if isinstance(results, dict) else {}

            # Generate very small HTML
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('<html><head><meta charset="utf-8"><title>SecAudit Report</title></head><body>')
                f.write('<h1>SecAudit Report</h1>')
                meta = data.get('metadata', {})
                f.write('<p>Processed entries: {}</p>'.format(meta.get('parsed_entries', 0)))
                f.write('<p>Threats detected: {}</p>'.format(meta.get('threats_detected', 0)))
                f.write('<pre>')
                f.write(str(data.get('threats', [])))
                f.write('</pre>')
                f.write('</body></html>')

            self.logger.info(f"HTML report written to: {filepath}")
            return True

        except Exception as e:
            self.logger.error(f"Error writing HTML report: {e}")
            return False
