# Steward terminal abstractions

Schema `1.0` models terminal authority as an explicit, revocable lease bound to one
host, node incarnation, actor, and exact workspace root. A managed task binding is
optional and never grants terminal access to an agent by implication.

Authority limits are intentionally finite: eight hours, 64 MiB input, 256 MiB
output/transcript, 128 arguments, and a 1000×1000 terminal. Transcript policy is
explicit (`None`, metadata only, or bounded full content). File-transfer flags are
independent capabilities.

Operational replay is a separate, short-lived lease policy. A positive replay
duration and byte quota permit bounded output recovery after disconnect even
when audit transcript mode is `None`; zero/zero forbids content retention and
readers receive an explicit `NotRetained` gap. Output reads carry exact
sequence/offset cursors and item/byte bounds. Input, resize, and close require
idempotency request IDs.
