"""RADAR collectors — candidate discovery, never feed writes.

Everything here produces files in triage/queue/ for a human to verify against a
primary source. No collector writes to data/entries/.
"""
