"""
Stream (real-time) input handler for SecAudit
"""
import sys
from typing import List, Generator, Dict, Any
from .base_input import BaseInput

class StreamInput(BaseInput):
    """Simple stream input that can read from STDIN or follow a generator"""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.encoding = config.get('encoding', 'utf-8')

    def read(self, source: str) -> List[str]:
        """Read all available lines from the provided stream source.

        If source is '-' it reads from STDIN until EOF.
        """
        if source == '-':
            return [line.rstrip('\n') for line in sys.stdin]
        raise NotImplementedError("StreamInput.read only supports '-' (stdin) in this stub")

    def read_stream(self, source: str) -> Generator[str, None, None]:
        if source == '-':
            for line in sys.stdin:
                yield line.rstrip('\n')
        else:
            raise NotImplementedError("StreamInput.read_stream only supports '-' (stdin) in this stub")
