import asyncio

import click

from isoforge import __version__
from isoforge.switch import run


@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="isoforge")
@click.pass_context
def main(ctx: click.Context) -> None:
    """ISO 8583 / EMV lab CLI. Localhost only."""
    if ctx.invoked_subcommand is None:
        click.echo("isoforge: pass --help for commands (more coming)")


@main.command("switch")
@click.option("--port", default=8583, show_default=True, type=click.IntRange(0, 65535))
def switch_command(port: int) -> None:
    """Answer 0800, 0200 and 0420 on 127.0.0.1."""
    asyncio.run(run(port))


if __name__ == "__main__":
    main()
