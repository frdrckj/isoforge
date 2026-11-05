# isoforge

ISO 8583 labs are messy. I wanted one small CLI I own for build, parse, mutate, and replay against a local mock switch.

isoforge is that lab. Python CLI for ISO 8583 messages (with EMV TLV in DE55) plus a mock switch that ships in this repo. Portfolio piece for payments appsec. Authorized lab only: localhost, synthetic test PANs, no real hosts, no PIN blocks, no HSM, no TLS.

## Install

```
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
isoforge --version
```

More commands land as the codec, TLV parser, mock switch, and fuzzer land. Until then this scaffold just proves the package and CI path.
