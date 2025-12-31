from .main import cli
from .commands import add_commands
from .utils import CLIUtils

# Add all command groups to the main CLI
add_commands(cli)

__all__ = [
    'cli',
    'add_commands',
    'CLIUtils'
]