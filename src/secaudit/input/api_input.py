"""
API input handler stub for SecAudit
"""
from typing import List, Dict, Any
from .base_input import BaseInput

class APIInput(BaseInput):
    """Placeholder for API-based log ingestion"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

    def read(self, source: str) -> List[str]:
        """In a full implementation this would call remote API endpoints.
        For the stub, raise NotImplementedError to indicate missing feature.
        """
        raise NotImplementedError("APIInput.read is not implemented in this stub")

    def read_stream(self, source: str):
        raise NotImplementedError("APIInput.read_stream is not implemented in this stub")
