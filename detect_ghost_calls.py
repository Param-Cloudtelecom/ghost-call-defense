#!/usr/bin/env python3
"""
detect_ghost_calls.py

Analyzes CDR history (the same `cdr` table from freeswitch-cloud-pbx) for
ghost-call / wangiri patterns that a simple per-second flood filter
(see kamailio/pike_flood_protection.cfg) won't catch on its own:

  - Many distinct calls from the same source, all hanging up in under
    N seconds, never answered - classic enumeration/wangiri behavior
    spread out slowly enough to stay under a burst threshold.
  - The same source calling a wide spread of destination numbers in a
    short window - extension/DID enumeration.

Flags offending source numbers/IPs for manual review or automatic
addition to a Kamailio block list.

Usage:
    export DATABASE_URL=postgresql://user:pass@localhost/freeswitch_cdr
    python detect_ghost_calls.py --window-minutes 60 --min-attempts 8 --max-duration 3
"""
import argparse
import os

import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/freeswitch_cdr")


def find_ghost_callers(window_minutes: int, min_attempts: int, max_duration: int):
    """
    A source is flagged if, within the window, it generated at least
    `min_attempts` calls that were never answered (billsec = 0 / duration
    under max_duration seconds) - the signature of scanning/wangiri abuse
    rather than a legitimate caller who happened to hang up once.
    """
    sql = """
        SELECT caller_id_number,
               count(*) AS attempt_count,
               count(DISTINCT destination_number) AS distinct_destinations,
               avg(duration_sec) AS avg_duration
        FROM cdr
        WHERE start_stamp > now() - interval '%s minutes'
          AND (billsec = 0 OR duration_sec <= %s)
          AND direction = 'inbound'
        GROUP BY caller_id_number
        HAVING count(*) >= %s
        ORDER BY attempt_count DESC
    """
    conn = psycopg2.connect(DATABASE_URL)
    with conn, conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, (window_minutes, max_duration, min_attempts))
        return cur.fetchall()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--window-minutes", type=int, default=60)
    parser.add_argument("--min-attempts", type=int, default=8,
                         help="Minimum unanswered/short calls in the window to flag a source")
    parser.add_argument("--max-duration", type=int, default=3,
                         help="Calls shorter than this (seconds) count as 'unanswered/ghost'")
    parser.add_argument("--block", action="store_true",
                         help="Print iptables/Kamailio ipban commands for flagged sources instead of just reporting")
    args = parser.parse_args()

    flagged = find_ghost_callers(args.window_minutes, args.min_attempts, args.max_duration)

    if not flagged:
        print(f"No ghost-call pattern detected in the last {args.window_minutes} minutes.")
        return

    print(f"{'Caller':<20}{'Attempts':<10}{'Distinct dest':<15}{'Avg duration':<12}")
    for row in flagged:
        print(f"{row['caller_id_number']:<20}{row['attempt_count']:<10}"
              f"{row['distinct_destinations']:<15}{float(row['avg_duration'] or 0):<12.1f}")

        if args.block:
            # Same ipban hash table referenced in kamailio.cfg / pike config -
            # this is the bridge from "detected in CDR analysis" to
            # "actually blocked at the SIP edge."
            print(f"  -> kamcmd htable.insert ipban {row['caller_id_number']} 1")


if __name__ == "__main__":
    main()
