#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
callwall — offline call-allowlist builder & verifier for Ethereum.

Modes
  build     → Ingest ABI JSON(s) → produce a policy JSON with allowed selectors and default rules
  verify    → Check raw tx hexes or calldatas against a policy (selector/value rules + simple pitfalls)
  scan      → Just list selectors found in inputs (inventory)
  svg-badge → Render a tiny pass/fail badge for a verification run

Why
  • Keep CI and reviewers honest: no unknown function calls slip through.
  • Enforce "value must be 0" unless explicitly permitted.
  • Catch common footguns without ABIs: approve(MAX), setApprovalForAll(true).

Examples
  $ python callwall.py build ./abis/*.json --default-value-wei 0 > policy.json
  $ python callwall.py verify policy.json txs.txt --pretty --json report.json --svg badge.svg
  $ cat calldata.txt | python callwall.py scan -
"""

import csv
import glob
import json
import os
import sys
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple

import click
import rlp
from eth_utils import keccak, to_checksum_address

# --------------------------- Helpers ---------------------------

def fourbyte(sig: str) -> str:
    return "0x" + keccak(text=sig)[:4].hex()

def norm_hex(s: str) -> str:
    s = s.strip()
    return s if s.startswith("0x") else "0x" + s

def strip0x(h: str) -> str:
    return h[2:] if h.startswith("0x") else h

def as_bytes(h: str) -> bytes:
    h = strip0x(h)
    if len(h) % 2 != 0:
        raise click.ClickException("Hex length must be even")
    try:
        return bytes.fromhex(h)
    except Exception as e:
        raise click.ClickException(f"Invalid hex: {e}")

def u256(b: bytes) -> int:
    return 0 if len(b) == 0 else int.from_bytes(b, "big")

def to_addr(b: bytes) -> Optional[str]:
    if len(b) == 0: return None
    if len(b) == 20:
        return to_checksum_address("0x" + b.hex())
    return to_checksum_address("0x" + b[-20:].hex())

def looks_calldata(s: str) -> bool:
    hs = s.strip().lower()
    return hs.startswith("0x") and len(hs) >= 10  # 4-byte selector min

# Selectors we can reason about without an ABI
SEL_APPROVE = "095ea7b3"
SEL_SET_APPROVAL_FOR_ALL = "a22cb465"

UINT256_MAX = (1 << 256) - 1

# --------------------------- ABI loading ---------------------------

def normalize_abi_type(t: str) -> str:
    return "uint256" if t == "uint" else "int256" if t == "int" else t

def fn_signature(name: str, inputs: List[Dict[str, Any]]) -> str:
    types = ",".join(normalize_abi_type(i.get("type","")) for i in inputs)
    return f"{name}({types})"

def load_abi(path: str) -> List[Dict[str, Any]]:
    """
    Accept:
      - Plain array ABI
      - Etherscan-style JSON with "result" stringified ABI
      - Objects with "abi": [...]
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("abi"), list):
            return data["abi"]
        if "result" in data:
            try:
                arr = json.loads(data["result"])
                if isinstance(arr, list): return arr
            except Exception:
                pass
    raise click.ClickException(f"Unrecognized ABI format: {path}")

# --------------------------- Policy model ---------------------------

@dataclass
class Policy:
    version: str
    allowed: List[Dict[str, Any]]   # [{selector,name?,rules?}]
    default_rules: Dict[str, Any]   # e.g., {"value_wei": 0}

def build_policy(paths: List[str], default_value_wei: Optional[int]) -> Policy:
    allowed: Dict[str, Dict[str, Any]] = {}
    files: List[str] = []
    for p in paths:
        xs = glob.glob(p) or ([p] if os.path.isfile(p) else [])
        files.extend(xs)
    if not files:
        raise click.ClickException("No ABI files found")
    for path in files:
        abi = load_abi(path)
        for item in abi:
            if item.get("type","function") != "function":
                continue
            sig = fn_signature(item.get("name",""), item.get("inputs",[]))
            sel = fourbyte(sig)
            allowed.setdefault(sel, {"selector": sel, "name": sig})
    return Policy(
        version="callwall.v1",
        allowed=sorted(allowed.values(), key=lambda x: x["selector"]),
        default_rules=({"value_wei": default_value_wei} if default_value_wei is not None else {})
    )

# --------------------------- TX decoding (legacy + 0x02) ---------------------------

def decode_raw_tx(raw_hex: str) -> Dict[str, Any]:
    h = strip0x(raw_hex).lower()
    b = bytes.fromhex(h)
    if len(b) == 0:
        raise click.ClickException("Empty tx bytes")
    out = {"type": "legacy", "fields": {}, "data": None}
    if b[0] == 0x02:
        lst = rlp.decode(b[1:], strict=False)
        if not isinstance(lst, list) or len(lst) < 12:
            raise click.ClickException("Malformed EIP-1559 tx")
        chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList, v, r, s = lst[:12]
        out["type"] = "eip-1559"
        out["fields"] = {
            "chainId": u256(chainId),
            "nonce": u256(nonce),
            "gasLimit": u256(gas),
            "to": to_addr(to),
            "value": u256(value),
        }
        out["data"] = "0x" + data.hex() if data else None
    else:
        lst = rlp.decode(b, strict=False)
        if not isinstance(lst, list) or len(lst) < 9:
            raise click.ClickException("Malformed legacy tx")
        nonce, gasPrice, gas, to, value, data, v, r, s = lst[:9]
        out["fields"] = {
            "nonce": u256(nonce),
            "gasLimit": u256(gas),
            "to": to_addr(to),
            "value": u256(value),
        }
        out["data"] = "0x" + data.hex() if data else None
    return out

# --------------------------- Pitfall checks (no ABI) ---------------------------

def pitfall_check(calldata_hex: str) -> List[str]:
    """
    Purely from selector + words, catch a few critical cases:
      - approve(address,uint256) with amount == 2^256-1
      - setApprovalForAll(address,bool) with bool == true
    """
    notes: List[str] = []
    h = strip0x(calldata_hex).lower()
    if len(h) < 8:
        return notes
    sel = h[:8]
    body = bytes.fromhex(h[8:])
    # two words for approve
    if sel == SEL_APPROVE and len(body) >= 64:
        amount = u256(body[32:64])
        if amount == UINT256_MAX:
            notes.append("HIGH: approve(MAX) detected")
    if sel == SEL_SET_APPROVAL_FOR_ALL and len(body) >= 64:
        flag = u256(body[32:64])  # bool encoded in last byte
        if flag == 1:
            notes.append("HIGH: setApprovalForAll(true)")
    return notes

# --------------------------- Verify core ---------------------------

def verify_against_policy(policy: Policy, inputs: List[str]) -> Dict[str, Any]:
    allowed = {a["selector"].lower(): a for a in policy.allowed}
    require_value = policy.default_rules.get("value_wei", None)

    results: List[Dict[str, Any]] = []
    ok_all = True

    for ln in inputs:
        item = ln.strip()
        if not item:
            continue
        entry = {
            "source": item[:80] + ("…" if len(item) > 80 else ""),
            "kind": None,
            "selector": None,
            "allowed": False,
            "value_ok": True,
            "pitfalls": [],
            "reason": None
        }
        try:
            if looks_calldata(item):
                entry["kind"] = "calldata"
                sel = strip0x(item)[:8].lower()
                entry["selector"] = "0x" + sel
                entry["allowed"] = ("0x"+sel) in allowed
                if not entry["allowed"]:
                    entry["reason"] = "selector not in policy"
                    ok_all = False
                # pitfall checks
                entry["pitfalls"] = pitfall_check(item)
                if entry["pitfalls"]:
                    ok_all = False
                # value rule cannot be enforced on pure calldata
            else:
                entry["kind"] = "rawtx"
                tx = decode_raw_tx(item)
                data = tx.get("data") or ""
                if not data:
                    entry["reason"] = "tx has no calldata"
                    entry["allowed"] = False
                    ok_all = False
                else:
                    sel = strip0x(data)[:8].lower()
                    entry["selector"] = "0x" + sel
                    entry["allowed"] = ("0x"+sel) in allowed
                    if not entry["allowed"]:
                        entry["reason"] = "selector not in policy"
                        ok_all = False
                    # value rule
                    if require_value is not None:
                        v = tx["fields"].get("value", 0)
                        entry["value_ok"] = (v == require_value)
                        if not entry["value_ok"]:
                            ok_all = False
                    # pitfalls
                    entry["pitfalls"] = pitfall_check(data)
                    if entry["pitfalls"]:
                        ok_all = False
        except click.ClickException as e:
            entry["reason"] = f"parse error: {e}"
            ok_all = False

        results.append(entry)

    return {"ok": ok_all, "results": results}

# --------------------------- CLI ---------------------------

@click.group(context_settings=dict(help_option_names=["-h","--help"]))
def cli():
    """callwall — build a call allowlist from ABIs and enforce it offline."""
    pass

@cli.command("build")
@click.argument("abi_paths", nargs=-1)
@click.option("--default-value-wei", type=int, default=None, help="Default rule: tx value must equal this (e.g., 0).")
def build_cmd(abi_paths, default_value_wei):
    """Build a policy JSON from one or more ABI files or globs."""
    pol = build_policy(list(abi_paths), default_value_wei)
    click.echo(json.dumps(asdict(pol), indent=2))

@cli.command("verify")
@click.argument("policy_path", type=str)
@click.argument("inputs", nargs=-1)
@click.option("--pretty", is_flag=True, help="Readable console output.")
@click.option("--json", "json_out", type=click.Path(writable=True), default=None, help="Write JSON report.")
@click.option("--svg", "svg_out", type=click.Path(writable=True), default=None, help="Write tiny SVG badge.")
def verify_cmd(policy_path, inputs, pretty, json_out, svg_out):
    """Verify calldatas or raw tx hexes from files/stdin inline against a policy."""
    with open(policy_path, "r", encoding="utf-8") as f:
        pol = Policy(**json.load(f))

    lines: List[str] = []
    if not inputs:
        raise click.ClickException("Provide at least one input path or '-' for stdin")
    for p in inputs:
        if p == "-":
            lines.extend([l.strip() for l in sys.stdin if l.strip()])
        elif os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as fh:
                lines.extend([l.strip() for l in fh if l.strip()])
        else:
            lines.append(p)

    rep = verify_against_policy(pol, lines)

    if pretty:
        status = "PASS ✅" if rep["ok"] else "FAIL ❌"
        click.echo(f"callwall — {status} ({len(rep['results'])} item(s))")
        for r in rep["results"]:
            sym = "✓" if (r["allowed"] and r["value_ok"] and not r["pitfalls"]) else "✗"
            sel = r["selector"] or "<none>"
            click.echo(f"  {sym}  {r['kind']:<6}  {sel}  {r['source']}")
            if r["reason"]:
                click.echo(f"     reason: {r['reason']}")
            if not r["value_ok"]:
                click.echo(f"     value rule violated")
            for n in r["pitfalls"]:
                click.echo(f"     pitfall: {n}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(rep, f, indent=2)
        click.echo(f"Wrote JSON report: {json_out}")

    if svg_out:
        color = "#3fb950" if rep["ok"] else "#f85149"
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="520" height="48" role="img" aria-label="callwall">
  <rect width="520" height="48" fill="#0d1117" rx="8"/>
  <text x="16" y="30" font-family="Segoe UI, Inter, Arial" font-size="16" fill="#e6edf3">
    callwall: {"PASS" if rep["ok"] else "FAIL"} — checked {len(rep['results'])} item(s)
  </text>
  <circle cx="495" cy="24" r="6" fill="{color}"/>
</svg>"""
        with open(svg_out, "w", encoding="utf-8") as f:
            f.write(svg)
        click.echo(f"Wrote SVG badge: {svg_out}")

    if not (pretty or json_out or svg_out):
        click.echo(json.dumps(rep, indent=2))

@cli.command("scan")
@click.argument("inputs", nargs=-1)
def scan_cmd(inputs):
    """List selectors seen in inputs (calldata or raw tx)."""
    lines: List[str] = []
    for p in inputs:
        if p == "-":
            lines.extend([l.strip() for l in sys.stdin if l.strip()])
        elif os.path.isfile(p):
            with open(p, "r", encoding="utf-8") as fh:
                lines.extend([l.strip() for l in fh if l.strip()])
        else:
            lines.append(p)

    sels: Dict[str,int] = {}
    for ln in lines:
        try:
            if looks_calldata(ln):
                sel = "0x"+strip0x(ln)[:8].lower()
                sels[sel] = sels.get(sel,0)+1
            else:
                tx = decode_raw_tx(ln)
                data = tx.get("data") or ""
                if data:
                    sel = "0x"+strip0x(data)[:8].lower()
                    sels[sel] = sels.get(sel,0)+1
        except Exception:
            pass
    for k,v in sorted(sels.items()):
        click.echo(f"{k} {v}")

if __name__ == "__main__":
    cli()
