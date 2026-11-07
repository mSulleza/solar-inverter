"""
Where decoded readings go.

Readings are written to a local SQLite spool first and only then pushed to Neon
Postgres. That ordering is the point: the collector runs on a machine at home,
on the same flaky link the inverter is on, and a dropped upload should never
mean a lost sample. Anything that fails to upload stays queued and goes up on
the next flush.

The Postgres connection string (Neon's DATABASE_URL) lives only here on the
collector. The dashboard never sees it -- it runs its own server-side queries
against the same database.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger("sink")

SPOOL_SCHEMA = """
create table if not exists spool (
    id integer primary key autoincrement,
    table_name text not null,
    body text not null,
    created_at real not null
);
create index if not exists spool_order on spool (id);
"""

# Only these columns exist on each target table; anything else in a row dict
# (units, stray derived keys) is dropped rather than crashing the insert.
COLUMNS: dict[str, tuple[str, ...]] = {
    "readings": (
        "logger_serial", "grid_voltage", "grid_frequency", "grid_power",
        "pv1_voltage", "pv1_current", "pv1_power",
        "pv2_voltage", "pv2_current", "pv2_power", "pv_power_total",
        "battery_voltage", "battery_current", "battery_power", "battery_soc",
        "load_voltage", "load_power",
        "inverter_temperature", "pv_energy_today", "load_energy_today",
        "profile", "registers",
    ),
    "raw_frames": (
        "logger_serial", "control_code", "control_name", "sequence",
        "checksum_ok", "modbus_crc_ok", "modbus_slave", "modbus_func",
        "registers", "payload_hex",
    ),
}


@dataclass
class NeonConfig:
    dsn: str
    # Uploads are batched; a bigger batch is fewer round-trips but a longer
    # window before rows land. The spool means nothing is lost either way.
    batch_size: int = 100
    timeout: float = 20.0


class Sink:
    def __init__(self, spool_path: Path, config: Optional[NeonConfig]) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(spool_path), check_same_thread=False)
        self._db.executescript(SPOOL_SCHEMA)
        self._db.commit()
        log.info("spool at %s", spool_path)
        if config is None:
            log.warning("no Neon config -- readings will spool locally only")

    def write(self, table: str, row: dict[str, Any]) -> None:
        with self._lock:
            self._db.execute(
                "insert into spool (table_name, body, created_at) values (?, ?, ?)",
                (table, json.dumps(row, default=str), time.time()),
            )
            self._db.commit()

    def pending(self) -> int:
        with self._lock:
            return self._db.execute("select count(*) from spool").fetchone()[0]

    def flush(self) -> int:
        """
        Push queued rows to Neon. Returns how many were accepted.

        Rows are deleted only inside the same transaction that inserts them, so a
        failure mid-flush rolls back and the next flush retries the same rows --
        at-least-once, never lost, never silently dropped.
        """
        if self.config is None:
            return 0

        try:
            import psycopg2
            from psycopg2.extras import execute_values
        except ImportError:
            log.error("psycopg2 not installed; cannot upload")
            return 0

        sent = 0
        try:
            conn = psycopg2.connect(self.config.dsn, connect_timeout=int(self.config.timeout))
        except Exception as exc:  # network down, bad creds, etc.
            log.warning("Neon unreachable (%s) -- rows stay queued", exc)
            return 0

        try:
            conn.autocommit = False
            while True:
                with self._lock:
                    rows = self._db.execute(
                        "select id, table_name, body from spool order by id limit ?",
                        (self.config.batch_size,),
                    ).fetchall()
                if not rows:
                    break

                by_table: dict[str, list[tuple[int, dict]]] = {}
                for row_id, table, body in rows:
                    by_table.setdefault(table, []).append((row_id, json.loads(body)))

                cur = conn.cursor()
                uploaded_ids: list[int] = []
                for table, entries in by_table.items():
                    cols = COLUMNS.get(table)
                    if cols is None:
                        # Unknown table -- drop it so it can't wedge the queue forever.
                        log.error("unknown table %s in spool; discarding", table)
                        uploaded_ids.extend(rid for rid, _ in entries)
                        continue
                    values = [tuple(entry.get(c) for c in cols) for _, entry in entries]
                    execute_values(
                        cur,
                        f'insert into public.{table} ({",".join(cols)}) values %s',
                        values,
                    )
                    uploaded_ids.extend(rid for rid, _ in entries)

                with self._lock:
                    self._db.executemany(
                        "delete from spool where id = ?", [(i,) for i in uploaded_ids]
                    )
                    conn.commit()
                    self._db.commit()
                sent += len(uploaded_ids)
        except Exception:
            conn.rollback()
            log.exception("flush failed; rows stay queued")
        finally:
            conn.close()

        return sent

    def close(self) -> None:
        with self._lock:
            self._db.close()
