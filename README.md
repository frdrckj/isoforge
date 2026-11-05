# isoforge

ISO 8583 labs are messy. I wanted one small CLI I own for build, parse, mutate, and replay against a local mock switch.

isoforge is that lab. It is a Python CLI for ISO 8583, with EMV TLV in DE55, and a mock switch that ships in this repo. Authorized lab only.

## One-command lab

```
docker compose up
isoforge send fixtures/0200.json
isoforge fuzz --seed 1 -n 500
```

`docker compose up` starts the switch and a lab container on one lab network. The only published port is `127.0.0.1:8583`. Send prints:

```
0210 DE39=00
```

## Install

```
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
isoforge --version
```

Without Docker, start the switch yourself:

```
isoforge switch --port 8583
```

## What the switch answers

| Request | Response | DE39 |
| --- | --- | --- |
| 0800 | 0810 | 00 |
| 0200 with a fixture PAN | 0210 | 00 |
| 0200 with any other PAN | 0210 | 14 |
| 0420 | 0430 | 00 |
| parse error, MTI readable | same class, response MTI | 30 |
| no readable MTI, or a frame over 8192 bytes | connection closed | |

0200 and the other replies echo DE11 and DE41 when the request has them. The fixture PANs are `4111111111111111` and `5555555555554444`.

## Scope and ethics

This is a lab. Use the test PANs above. Keep it on localhost. Do not point it at a real host, a real switch, or a cardholder PAN.

There is no PIN block, no MAC, no HSM, and no TLS. `--i-own-this-target` turns off the loopback check. I still do not use it against anything I do not own, and I do not use it against a live payment host.

Run logs go in `runs/`. DE2 is stored as the first 6 and last 4. The DE55 hex is kept. The full PAN is not written.

## A fuzz run

I ran `isoforge fuzz --seed 1 -n 500` against the compose switch. Same seed, same cases. A crash means the switch stops answering a later 0800.

| | |
| --- | --- |
| cases | 500 |
| crashes | 0 |
| bitmap_flip | 121 |
| length_overflow | 123 |
| field_truncation | 130 |
| bad_tlv_length | 126 |
| reply DE39=30 | 475 |
| reply DE39=00 | 22 |
| closed | 3 |

Most mutations are format errors. The switch reads an MTI and returns DE39=30. Three frames had no readable MTI, so the switch closed those connections. Twenty two mutations still parsed as an 0200 with an allowed PAN, so the switch approved them. A flipped bit does not always break the message. After every case, including those, the switch still answered 0800 with 0810 and DE39=00.
