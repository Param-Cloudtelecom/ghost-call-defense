# ghost-call-defense

![License](https://img.shields.io/github/license/Param-Cloudtelecom/ghost-call-defense) ![Top Language](https://img.shields.io/github/languages/top/Param-Cloudtelecom/ghost-call-defense) ![Last Commit](https://img.shields.io/github/last-commit/Param-Cloudtelecom/ghost-call-defense)


Detection and mitigation for **ghost calls** — SIP scanning bursts and
short, unanswered "wangiri"-style calls designed to bait a callback to a
premium-rate number, or to enumerate which extensions/DIDs are live on a
PBX. This is a defensive security tool, not an offensive one — it exists
to protect a Cloud PBX platform's subscribers and infrastructure.

## Two layers of defense, because one isn't enough

**1. Fast path — Kamailio `pike` module** ([`kamailio/pike_flood_protection.cfg`](kamailio/pike_flood_protection.cfg))

Tracks request rate per source IP and auto-blocks anything bursting past a
threshold (default: >30 requests/2s) before it ever reaches `usrloc` or a
tenant's dialplan. This catches loud, fast scanning — but a patient
attacker spreading the same enumeration out over an hour stays under any
reasonable burst threshold.

**2. Slow path — CDR pattern analysis** ([`detect_ghost_calls.py`](detect_ghost_calls.py))

Runs against the same `cdr` table from
[`freeswitch-cloud-pbx`](https://github.com/Param-Cloudtelecom/freeswitch-cloud-pbx)
and flags any source generating a high volume of unanswered/very-short
calls within a rolling window — the signature of slow enumeration or
wangiri abuse that a per-second rate limiter won't catch. Flagged sources
can be fed straight back into the same `ipban` hash table the Kamailio
layer already checks, closing the loop between detection and enforcement.

```
                    fast (seconds)                 slow (minutes/hours)
 SIP traffic ──► pike.so burst check ──► dialplan ──► CDR table
                       │                                  │
                       ▼                                  ▼
                  ipban htable ◄──────── detect_ghost_calls.py --block
```

## Usage

```bash
# Kamailio side: include in kamailio.cfg (see kamailio-sbc-router for the
# full routing config this plugs into)
#!define WITH_GHOST_CALL_DEFENSE
include_file "kamailio/pike_flood_protection.cfg"

# CDR analysis: report only
export DATABASE_URL=postgresql://user:pass@localhost/freeswitch_cdr
python detect_ghost_calls.py --window-minutes 60 --min-attempts 8

# CDR analysis: report AND print the commands to block flagged sources
python detect_ghost_calls.py --window-minutes 60 --min-attempts 8 --block
```

## Why I built it this way

A single rate-limit threshold is always a trade-off between false
positives (blocking a legitimately busy call center) and false negatives
(missing a patient attacker). Splitting detection into a fast burst check
and a slower pattern-over-time check means each layer can be tuned
aggressively for its own timescale without either one having to be the
single point of failure.
