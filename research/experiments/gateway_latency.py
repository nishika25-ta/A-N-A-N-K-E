"""Measure gateway decision latency (engineering target: p95 < 50 ms at 1,000 simple rules).

Run:  uv run python research/experiments/gateway_latency.py [--rules 1000] [--requests 1000]

Workload (documented, synthetic, local): N GRANT rules for one principal on distinct ticket
resources; requests alternate between an allowed read on an existing rule's resource and a
denied read on an ungranted resource, with unique idempotency keys. The SQLite file lives on the
local disk with synchronous=FULL. The timings cover the full ``AgentPort.propose`` call
(validation, verified policy load, evaluation, effect, decision record, COMMIT/fsync).
The results depend on hardware and filesystem. Report them with the machine description; never
reuse them as a general claim.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

from ananke.domain import LogicalClock, PolicyChange
from ananke.lab import seed_records
from ananke.ledger import OperatorChannel, init_ledger, open_ledger
from ananke.ledger.db import write_transaction
from ananke.runtime import AgentPort, Gateway


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", type=int, default=1000)
    ap.add_argument("--requests", type=int, default=1000)
    ns = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "bench.sqlite"
        init_ledger(db, ["op-admin"])
        conn = open_ledger(db)
        clock = LogicalClock()
        op = OperatorChannel(conn, "op-admin", clock.now)
        op.submit_many(
            [
                PolicyChange(
                    kind="GRANT",
                    rule_id=f"g{i}",
                    principal_id="agent-bench",
                    tool_id="ticket",
                    operation="read",
                    resource_scope=f"ticket:t{i}",
                    valid_from=0,
                )
                for i in range(ns.rules)
            ]
        )
        with write_transaction(conn) as c:
            seed_records(c, {f"ticket:t{i}": {"title": f"t{i}"} for i in range(ns.rules)})
        port = AgentPort(Gateway(conn, clock.now), principal_id="agent-bench", session_id="s")
        samples: list[float] = []
        outcomes: dict[str, int] = {}
        for i in range(ns.requests):
            res = f"ticket:t{i % ns.rules}" if i % 2 == 0 else f"ticket:x{i}"
            t0 = time.perf_counter()
            r = port.propose(
                {
                    "tool_id": "ticket",
                    "operation": "read",
                    "resource": res,
                    "idempotency_key": f"k{i}",
                }
            )
            samples.append((time.perf_counter() - t0) * 1000)
            outcomes[r.reason_code.value] = outcomes.get(r.reason_code.value, 0) + 1
        conn.close()
    samples.sort()
    q = statistics.quantiles(samples, n=100)
    print(
        json.dumps(
            {
                "workload": {"rules": ns.rules, "requests": ns.requests},
                "machine": {
                    "python": sys.version.split()[0],
                    "platform": platform.platform(),
                    "processor": platform.processor() or "unknown",
                },
                "latency_ms": {
                    "p50": round(q[49], 3),
                    "p95": round(q[94], 3),
                    "p99": round(q[98], 3),
                    "max": round(samples[-1], 3),
                },
                "outcomes": outcomes,
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
