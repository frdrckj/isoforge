from click.testing import CliRunner

import isoforge
from isoforge.cli import main


def test_version_flag() -> None:
    result = CliRunner().invoke(main, ["--version"])
    assert result.exit_code == 0
    assert isoforge.__version__ in result.output


def test_package_version() -> None:
    assert isoforge.__version__ == "0.1.0"
