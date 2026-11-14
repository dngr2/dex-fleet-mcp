#!/usr/bin/env python3
"""dryrun.py — call every tool once and print the transcript. Nothing is signed or broadcast.

  python3 dryrun.py            # simulate (eth_call every payload — needs RPC)
  python3 dryrun.py --nosim    # build calldata only — offline, no RPC

`run_all(dry_run)` is reused by selftest.py with dry_run=False (calldata-only, no network).
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import server as S

# a plausible, fixed set of args (Base USDC, a scratch destination) — nothing sensitive.
# SIM_FROM is used as the payer/sender so approve legs have a real caller identity in the sim.
DEST = "0x000000000000000000000000000000000000dEaD"
SIM_FROM = S.SIM_FROM
USDC = S.spec.USDC
FACTORY = S.spec.ADDR["g2a-streams"]
DEX = "0x4200000000000000000000000000000000000006"  # WETH on Base
HOP_D = [1, DEX, USDC, 500, DEX]  # duster hop: venue,tokenIn,tokenOut,feeTier,venueRouter
HOP_R = [1, DEX, USDC, 500, True, DEX, FACTORY]  # router hop: +stable,+factory
TOTAL = 22  # 19 call tools + 3 meta (read_fee, read_x402_status, server_info)


def run_all(dry_run: bool = True) -> int:
    """Call each tool once. Returns the number of tools called. Used by selftest."""
    secret = json.loads(S.escrow_new_secret())
    calls = [
        lambda: S.create_pay_link(destination=DEST, amount=5_000_000, memo="invoice-42", dry_run=dry_run),
        lambda: S.resolve_pay_link(tx_hash="0x" + "ab" * 32),
        lambda: S.register_deposit_address(destination=DEST, dry_run=dry_run),
        lambda: S.pay(destination=DEST, amount=5_000_000, dry_run=dry_run),
        lambda: S.escrow_create(counterparty=DEST, amount=10_000_000,
                                hashlock=secret["hashlock"], timeout=1_800_000_000, dry_run=dry_run),
        lambda: S.escrow_new_secret(),
        lambda: S.escrow_release(escrow="0x" + "22" * 20, which="release",
                                 preimage=secret["preimage"], dry_run=dry_run),
        lambda: S.stream_create(recipient=DEST, amount=100_000_000, start=1_700_000_000,
                                end=1_700_086_400, dry_run=dry_run),
        lambda: S.subscribe(payer=SIM_FROM, recipient="0x" + "44" * 20, amount=1_000_000,
                            start=1_700_000_000, end=1_700_086_400, periods=12, dry_run=dry_run),
        lambda: S.disarm_mandate(recipient="0x" + "44" * 20, issuer=SIM_FROM, dry_run=dry_run),
        lambda: S.pay_x402(payment_id="0x" + "ab" * 32, to=DEST, amount=1_000_000,
                           writer=SIM_FROM, dry_run=dry_run),
        lambda: S.read_402_challenge(url="https://dngr2.github.io/dex-products/llms.txt"),
        lambda: S.read_capabilities(payer=SIM_FROM, product="x402"),
        lambda: S.swap(amount_in=1_000_000, amount_out_min=990_000, hops=[HOP_R],
                       recipient=DEST, dry_run=dry_run),
        lambda: S.quote_swap(hops=[[DEX, USDC, 500]], amount_in=1_000_000, dry_run=dry_run),
        lambda: S.sweep_dust(tokens=[DEX], hops=[HOP_D], min_out=[990_000], dry_run=dry_run),
        lambda: S.quote_sweep(tokens=[DEX], hops=[HOP_D], dry_run=dry_run),
        lambda: S.sponsored_call(calls=[[DEST, 0, "0x12345678"]], dry_run=dry_run),
        lambda: S.mint_receipt(escrow="0x" + "55" * 20, dry_run=dry_run),
        lambda: S.read_fee(),           # always live (its own RPC)
        lambda: S.read_x402_status(payment_id="0x" + "ab" * 32),
        lambda: S.server_info(),
    ]
    n = 0
    for c in calls:
        try:
            out = c()
            n += 1
            print(out)
            print("-" * 70)
        except Exception as e:  # noqa: BLE001
            print(f"!! tool failed: {type(e).__name__}: {e}")
            print("-" * 70)
    return n


if __name__ == "__main__":
    dry = "--nosim" not in sys.argv
    print(f"# dryrun: simulate={dry}  (mcp will be launched WITHOUT python3 -I)\n")
    k = run_all(dry_run=dry)
    print(f"# called {k}/{TOTAL} tools")
