import asyncio
import json
from pathlib import Path

import click

from isoforge import __version__
from isoforge.client import DEFAULT_TIMEOUT, ClientError, send
from isoforge.fuzz import execute
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


@main.command("send")
@click.argument("fixture", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8583, show_default=True, type=click.IntRange(0, 65535))
@click.option("--timeout", default=DEFAULT_TIMEOUT, show_default=True, type=float)
@click.option("--i-own-this-target", is_flag=True, help="Allow a host that is not loopback.")
def send_command(
    fixture: Path,
    host: str,
    port: int,
    timeout: float,
    i_own_this_target: bool,
) -> None:
    """Send one fixture and print the response MTI and DE39."""
    fields = json.loads(fixture.read_text())
    try:
        reply = send(
            host,
            port,
            fields,
            timeout=timeout,
            allow_remote=i_own_this_target,
        )
    except ClientError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"{reply.get('t')} DE39={reply.get('39')}")


@main.command("fuzz")
@click.option("--seed", required=True, type=int)
@click.option("-n", "count", required=True, type=click.IntRange(1, 100000))
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8583, show_default=True, type=click.IntRange(0, 65535))
@click.option("--timeout", default=1.0, show_default=True, type=float)
def fuzz_command(seed: int, count: int, host: str, port: int, timeout: float) -> None:
    """Mutate the 0200 fixture and record how the switch answers."""
    try:
        summary = execute(seed, count, host, port, timeout)
    except ClientError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(summary.text())
    if summary.crashes:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
