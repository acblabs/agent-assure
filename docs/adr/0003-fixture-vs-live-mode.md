# ADR 0003: Fixture vs Live Mode

v0.1 used fixture mode and rejected live execution from fixture commands. The
current implementation keeps fixture commands deterministic and exposes live
execution only through the separate `agent-assure live` command namespace.
