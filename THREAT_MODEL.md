# Threat model

isoforge is a lab. The only network boundary is the CLI talking to the mock switch over TCP.

Both sides treat the bytes as untrusted. A frame longer than 8192 bytes is dropped. A parse error becomes DE39=30 when the MTI can be read, and a close when it cannot. One bad client does not stop the server. Nothing is passed to eval.

The switch binds 127.0.0.1 and refuses any other host. It never binds 0.0.0.0. Inside Compose it also listens on the container's own addresses, because Docker delivers the published port there. Compose publishes only 127.0.0.1:8583. The lab service sits on an internal network and has no published port. The switch is also on a second network so Docker can map the port. That second network can route out. The lab network cannot. The client refuses a non-loopback host unless you pass `--i-own-this-target`. That flag is still not a reason to point this at a real host.

There are no keys, PIN blocks, or real PANs in v1. Fixtures use the test PANs 4111111111111111 and 5555555555554444. A test fails if a fixture PAN is outside that list. Run logs keep the first 6 and last 4 of DE2, and they keep the DE55 hex.

Dependencies are pinned. CI runs pip-audit.
