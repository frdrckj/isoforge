import click

from isoforge import __version__


@click.command()
@click.version_option(version=__version__, prog_name="isoforge")
def main() -> None:
    """ISO 8583 / EMV lab CLI. Localhost only."""
    click.echo("isoforge: pass --help for commands (more coming)")


if __name__ == "__main__":
    main()
