import sys
from pathlib import Path

import pytest

# Let tests `from fakes import ...` without making tests/ a package.
sys.path.insert(0, str(Path(__file__).parent))

SAMPLE_DATA = Path(__file__).resolve().parent.parent / "sample_data"


@pytest.fixture
def sample_data() -> Path:
    return SAMPLE_DATA
