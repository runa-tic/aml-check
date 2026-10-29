#!/usr/bin/env python3
"""Free AML screen for an EVM address (Ethereum, BNB Chain, Arbitrum).

Checks, per chain:
  1. Sanctions  - Chainalysis on-chain sanctions oracle (OFAC SDN etc.), free, no key.
  2. Freezes    - is the address frozen by the USDT / USDC contracts on that chain.
  3. Contacts   - every address it has transacted with, screened for sanctions,
                  stablecoin freezes and Tornado Cash contracts.

Check 3 needs transaction history:
  eth - Etherscan if ETHERSCAN_API_KEY is set, else keyless Blockscout (10 requests per
        ~hour per IP, i.e. about three scans an hour)
  arb - Etherscan V2 with a free key (ETHERSCAN_API_KEY)
  bsc - Etherscan V2 with a PAID key (Etherscan dropped BNB from the free tier in 2025); the
        key is tried as is, and BNB Chain is skipped if Etherscan refuses it
A free key (etherscan.io/myapikey) covers eth + arb at 5 req/s. It is read from
ETHERSCAN_API_KEY, else from ~/.config/aml-check/etherscan_key.

With history available, it also traces exposure (see exposure.py): the share of the address's
incoming and outgoing USD value that comes from or goes to sanctioned, mixer, stolen-funds,
exchange, bridge and other labelled sources, up to --hops wallets away.

Usage:
  python aml_check.py 0xYourAddress
  python aml_check.py 0xYourAddress --details          # + gas balance and latest transfers
  python aml_check.py 0xYourAddress --chains eth,arb --max-tx 1000
  python aml_check.py 0xYourAddress --hops 3 --budget 40   # deeper exposure trace
  python aml_check.py 0xYourAddress --hops 0               # direct contacts only

Exit code: 0 = nothing found, 1 = red flag found, 2 = error.
This is public-data screening only; it is not what an exchange's own vendor will see.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import exposure

UA = {"User-Agent": "aml-check/1.0", "Content-Type": "application/json"}

ORACLE = "0x40C57923924B5c5c5455c48D93317139ADDaC8fb"  # Chainalysis SanctionsList, same address on all three chains

SEL_IS_SANCTIONED = "df592f7d"   # isSanctioned(address)
SEL_USDT_LEGACY = "e47d6060"     # isBlackListed(address)  - USDT on Ethereum
SEL_USDT0 = "fbac3951"           # isBlocked(address)      - USDT0 on Arbitrum
SEL_CIRCLE = "fe575a87"          # isBlacklisted(address)  - Circle USDC

CHAINS = {
    "eth": {
        "name": "Ethereum",
        "gas": "ETH",
        "id": 1,
        "rpc": "https://ethereum-rpc.publicnode.com",
        "blockscout": "https://eth.blockscout.com/api",
        "free_etherscan": True,
        "freeze": [("USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7", SEL_USDT_LEGACY),
                   ("USDC", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", SEL_CIRCLE)],
    },
    "bsc": {
        "name": "BNB Chain",
        "gas": "BNB",
        "id": 56,
        "rpc": "https://bsc-rpc.publicnode.com",
        "blockscout": None,
        "free_etherscan": False,
        # Binance-Peg USDT/USDC have no on-chain freeze function; Binance controls them off-chain.
        "freeze": [],
    },
    "arb": {
        "name": "Arbitrum",
        "gas": "ETH",
        "id": 42161,
        "rpc": "https://arbitrum-one-rpc.publicnode.com",
        "blockscout": None,  # arbitrum.blockscout.com sits behind a Cloudflare challenge
        "free_etherscan": True,
        "freeze": [("USDT0", "0xFd086bC7CD5C481DCC9C85ebE478A1C0b69FCbb9", SEL_USDT0),
                   ("USDC", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", SEL_CIRCLE)],
    },
}

# Tornado Cash contracts. Names verified against explorer contract names (eth); pool
# bytecode on BSC/Arbitrum matches across chains. OFAC delisted Tornado in 2025, so the
# oracle no longer flags these, but exchanges still treat contact with them as high risk.
TORNADO = {
    "eth": {
        "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc": "Tornado 0.1 ETH",
        "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936": "Tornado 1 ETH",
        "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado 10 ETH",
        "0xa160cdab225685da1d56aa342ad8841c3b53f291": "Tornado 100 ETH",
        "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b": "Tornado Router",
        "0x722122df12d4e14e13ac3b6895a86e84145b6967": "Tornado Proxy",
        "0xd96f2b1c14db8458374d9aca76e26c3d18364307": "Tornado USDC 100",
        "0x4736dcf1b7a3d580672cce6e7c65cd5cc9cfba9d": "Tornado USDC 1000",
        "0x169ad27a470d064dede56a2d3ff727986b15d52b": "Tornado USDT 100",
        "0x0836222f2b2b24a3f36f98668ed8f0b38d1a872f": "Tornado USDT 1000",
        "0xd4b88df4d29f5cedd6857912842cff3b20c8cfa3": "Tornado DAI 100",
        "0xfd8610d20aa15b7b2e3be39b396a1bc3516c7144": "Tornado DAI 1000",
    },
    "_multichain": {  # same addresses on BSC and Arbitrum
        "0x84443cfd09a48af6ef360c6976c5392ac5023a1f": "Tornado pool (0.1)",
        "0xd47438c816c9e7f2e2888e060936a499af9582b3": "Tornado pool (1)",
        "0x330bdfade01ee9bf63c209ee33102dd334618e0a": "Tornado pool (10)",
        "0x1e34a77868e19a6647b1f2f47b51ed72dede95dd": "Tornado pool (100)",
        "0x0d5550d52428e7e3175bfc9550207e4ad3859b17": "Tornado proxy",
    },
}


def tornado_label(chain, addr):
    return TORNADO.get(chain, {}).get(addr) or (TORNADO["_multichain"].get(addr) if chain != "eth" else None)


def http_json(url, body=None, retries=3):
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers=UA)
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if attempt == retries - 1:
                raise
            time.sleep((5 if e.code == 429 else 1.5) * (attempt + 1))
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(1.5 * (attempt + 1))


def word(addr):
    return addr.lower()[2:].rjust(64, "0")


def eth_calls(chain, calls):
    """calls: list of (to, data). Returns list of int results, or None where the call reverted."""
    rpc = CHAINS[chain]["rpc"]
    out = [None] * len(calls)

    def one(i):
        to, data = calls[i]
        r = http_json(rpc, {"jsonrpc": "2.0", "id": i, "method": "eth_call",
                            "params": [{"to": to, "data": data}, "latest"]})
        res = r.get("result")
        if res and res != "0x":
            out[i] = int(res, 16)

    # JSON-RPC batch first; fall back to parallel single calls if the node refuses batches.
    for start in range(0, len(calls), 25):
        chunk = list(range(start, min(start + 25, len(calls))))
        try:
            resp = http_json(rpc, [{"jsonrpc": "2.0", "id": i, "method": "eth_call",
                                    "params": [{"to": calls[i][0], "data": calls[i][1]}, "latest"]}
                                   for i in chunk])
            if not isinstance(resp, list):
                raise ValueError("no batch")
            for item in resp:
                res = item.get("result")
                if res and res != "0x":
                    out[item["id"]] = int(res, 16)
        except Exception:
            with ThreadPoolExecutor(max_workers=6) as ex:
                list(ex.map(one, chunk))
    return out


def screen(chain, addrs):
    """For each address: sanctioned?, frozen by which stablecoins?, Tornado label."""
    cfg = CHAINS[chain]
    calls, index = [], []
    for a in addrs:
        calls.append((ORACLE, "0x" + SEL_IS_SANCTIONED + word(a)))
        index.append((a, "sanctions"))
        for sym, token, sel in cfg["freeze"]:
            calls.append((token, "0x" + sel + word(a)))
            index.append((a, sym))
    results = eth_calls(chain, calls)
    report = {a: {"sanctioned": None, "frozen_by": [], "unchecked": [], "tornado": tornado_label(chain, a)}
              for a in addrs}
    for (a, what), val in zip(index, results):
        if what == "sanctions":
            report[a]["sanctioned"] = None if val is None else bool(val)
        elif val is None:
            report[a]["unchecked"].append(what)
        elif val:
            report[a]["frozen_by"].append(what)
    return report


def etherscan_get(url, retries=4):
    """GET an Etherscan-style API, waiting out its rate limit (reported as HTTP 200 + status 0)."""
    for attempt in range(retries):
        r = http_json(url)
        if "rate limit" not in str(r.get("result", "")).lower() or attempt == retries - 1:
            return r
        time.sleep(1.0 * (attempt + 1))


def history(chain, addr, key, max_tx):
    """Returns (transfers, source, note). transfers: list of dicts with from/to/value/symbol."""
    cfg = CHAINS[chain]
    if key:
        base, src = "https://api.etherscan.io/v2/api", "Etherscan"
        extra = {"chainid": cfg["id"], "apikey": key}
    elif cfg["blockscout"]:
        base, src, extra = cfg["blockscout"], "Blockscout", {}
    elif chain == "bsc":
        return None, None, "needs a paid Etherscan key (set ETHERSCAN_API_KEY and ETHERSCAN_PAID=1)"
    else:
        return None, None, "needs a free Etherscan key (set ETHERSCAN_API_KEY)"

    rows, truncated = [], False
    for action in ("txlist", "tokentx", "txlistinternal"):
        q = {"module": "account", "action": action, "address": addr, "page": 1,
             "offset": max_tx, "sort": "desc", **extra}
        r = etherscan_get(base + "?" + urllib.parse.urlencode(q))
        res = r.get("result")
        if r.get("status") != "1" or not isinstance(res, list):
            msg = (r.get("message", "") + " " + str(res)).lower()
            if not cfg["free_etherscan"] and ("not supported" in msg or "upgrade" in msg):
                return None, None, "needs a paid Etherscan key"
            if isinstance(res, str) and "no transactions" not in msg:
                return None, src, f"{action}: {res[:120]}"
            continue
        truncated |= len(res) >= max_tx
        for t in res:
            if t.get("isError") == "1":
                continue  # reverted: the value never moved
            dec = int(t.get("tokenDecimal") or 18)
            rows.append({"from": (t.get("from") or "").lower(), "to": (t.get("to") or "").lower(),
                         "value": int(t.get("value") or 0) / 10 ** dec, "raw": int(t.get("value") or 0),
                         "symbol": t.get("tokenSymbol") or cfg["gas"],
                         "token": (t.get("contractAddress") or "").lower() if action == "tokentx" else "",
                         "time": int(t.get("timeStamp") or 0), "hash": t.get("hash")})
        time.sleep(0.25)  # stay under free-tier rate limits
    note = f"only the latest {max_tx} per type were read" if truncated else None
    return rows, src, note


def fmt_time(ts):
    return time.strftime("%Y-%m-%d", time.gmtime(ts)) if ts else "?"


KEY_FILE = os.path.join(os.path.expanduser("~"), ".config", "aml-check", "etherscan_key")


def load_key():
    """ETHERSCAN_API_KEY, else the key file, so a caller never has to put the key on a command line."""
    key = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if not key and os.path.isfile(KEY_FILE):
        with open(KEY_FILE, encoding="utf-8") as f:
            key = f.read().strip()
    return key or None


def native_balance(chain, addr):
    r = http_json(CHAINS[chain]["rpc"], {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance",
                                         "params": [addr, "latest"]})
    return int(r["result"], 16) / 1e18


def print_exposure(chain, exp):
    gas = CHAINS[chain]["gas"]
    if "skipped" in exp:
        print(f"   exposure     skipped: {exp['skipped']}")
        return
    inn, out = exp["in"], exp["out"]
    if inn["usd"] <= 0 and out["usd"] <= 0:
        print("   exposure     no priced transfers (native coin or major stablecoins) to trace")
        return
    read = inn["wallets_read"] + out["wallets_read"]
    print(f"   exposure     in ${inn['usd']:,.0f} / out ${out['usd']:,.0f}, traced {inn['hops']} hops"
          f", {read} wallets read, {exp['seconds']}s")
    failed = inn.get("failed_reads", 0) + out.get("failed_reads", 0)
    if failed:
        print(f"                note: {failed} wallet histories could not be read; their share is untraced")
    if not exp["priced_natives"]:
        print(f"                note: no {gas} price, so only stablecoin transfers were counted")
    for side, word in (("in", "from"), ("out", "to")):
        for x in exp[side].get("crossings", [])[:3]:
            print(f"                via Aori: {x['share'] * 100:.1f}% of {side}flow {word} "
                  f"{x['address']} on {CHAINS[x['chain']]['name']}")
    order = ["severe", "high", "medium", "low", None]
    usd = inn["usd"] + out["usd"]
    rows = []
    for cat in set(inn["categories"]) | set(out["categories"]):
        ci, co = inn["categories"].get(cat, {}), out["categories"].get(cat, {})
        total = (ci.get("share", 0) * inn["usd"] + co.get("share", 0) * out["usd"]) / usd
        if total < 0.0005:
            continue  # prints as 0.0%; red-flag lines start at 0.1%
        direct = ci.get("direct", 0) + co.get("direct", 0)
        indirect = ci.get("indirect", 0) + co.get("indirect", 0)
        how = "direct+indirect" if direct and indirect else "direct" if direct else "indirect"
        weight = {}
        for side, c in ((inn, ci), (out, co)):
            for n, w in c.get("names", []):
                weight[n] = weight.get(n, 0) + w * side["usd"]
        names = ""
        for n in sorted(weight, key=lambda n: -weight[n]):
            if len(names) + len(n) > 70:
                break
            names += (", " if names else "") + n
        rows.append((order.index(exposure.RISK.get(cat)), -total, cat, ci, co, total, how, names))
    print("                  total     in    out  category          risk     how")
    pct = lambda c: f"{c['share'] * 100:5.1f}%" if c else "     -"
    for _, _, cat, ci, co, total, how, names in sorted(rows):
        risk = exposure.RISK.get(cat) or "-"
        mark = "!!" if risk in ("severe", "high") else "  "
        print(f"              {mark} {total * 100:5.1f}% {pct(ci)} {pct(co)}  {cat:<17} {risk:<8} {how}")
        if names:
            print(f"                                         {names[:70]}")


def main():
    p = argparse.ArgumentParser(description="Free AML screen for an EVM address.")
    p.add_argument("address")
    p.add_argument("--chains", default="eth,bsc,arb", help="comma list from: eth,bsc,arb")
    p.add_argument("--max-tx", type=int, default=1000, help="max records per history type (free Etherscan caps at 1000)")
    p.add_argument("--json", action="store_true", help="print machine-readable result")
    p.add_argument("--details", action="store_true", help="also show gas balance and the latest transfers")
    p.add_argument("--hops", type=int, default=4, help="how many wallets away to trace exposure (0 = off)")
    p.add_argument("--budget", type=int, default=25,
                   help="max wallets whose history is read per direction during each chain's trace")
    a = p.parse_args()

    addr = a.address.strip().lower()
    if not (addr.startswith("0x") and len(addr) == 42 and all(c in "0123456789abcdef" for c in addr[2:])):
        print("not an EVM address (expected 0x + 40 hex chars)", file=sys.stderr)
        return 2
    key = load_key()
    chains = [c.strip() for c in a.chains.split(",") if c.strip()]
    bad = [c for c in chains if c not in CHAINS]
    if bad:
        print(f"unknown chain(s): {', '.join(bad)}", file=sys.stderr)
        return 2

    result, red = {"address": addr, "chains": {}}, False
    for chain in chains:
        cfg = CHAINS[chain]
        out = {}
        try:
            own = screen(chain, [addr])[addr]
        except Exception as e:
            out["error"] = f"RPC failed: {e}"
            result["chains"][chain] = out
            continue
        out["self"] = own
        red |= bool(own["sanctioned"]) or bool(own["frozen_by"])
        if a.details:
            try:
                out["native_balance"] = native_balance(chain, addr)
            except Exception:
                out["native_balance"] = None

        try:
            rows, src, note = history(chain, addr, key, a.max_tx)
        except Exception as e:
            rows, src, note = None, "history", f"request failed ({e}); try again in a minute"
        out["truncated"] = bool(note and note.startswith("only the latest"))
        out["history_source"], out["history_note"] = src, note
        if rows is not None:
            # Token contracts appear as counterparties; Circle blacklists its own USDC contract,
            # so these would show up as false "frozen" hits.
            tokens = {t.lower() for _, t, _ in cfg["freeze"]}
            stats = {}
            for t in rows:
                other = t["to"] if t["from"] == addr else t["from"]
                if not other or other == addr or other == "0x" + "0" * 40 or other in tokens:
                    continue
                s = stats.setdefault(other, {"n": 0, "in": 0, "out": 0, "last": 0})
                s["n"] += 1
                s["in" if t["to"] == addr else "out"] += 1
                s["last"] = max(s["last"], t["time"])
            flags = []
            if stats:
                rep = screen(chain, list(stats))
                for other, r in rep.items():
                    why = []
                    if r["sanctioned"]:
                        why.append("SANCTIONED")
                    if r["frozen_by"]:
                        why.append("frozen by " + "/".join(r["frozen_by"]))
                    if r["tornado"]:
                        why.append(r["tornado"])
                    if why:
                        flags.append({"address": other, "why": why, **stats[other]})
            out["transfers"] = len(rows)
            out["counterparties"] = len(stats)
            out["first_seen"] = fmt_time(min((t["time"] for t in rows), default=0))
            out["flagged_counterparties"] = sorted(flags, key=lambda f: -f["n"])
            red |= bool(flags)
            if a.hops > 0 and rows:
                try:
                    out["exposure"] = exposure.run(sys.modules[__name__], chain, addr, rows, key, a.hops, a.budget)
                    red |= bool(exposure.red_flags(out["exposure"]))
                except Exception as e:
                    out["exposure_error"] = f"trace failed ({e})"
            if a.details:
                out["recent"] = [{"time": t["time"], "dir": "in" if t["to"] == addr else "out",
                                  "counterparty": t["from"] if t["to"] == addr else t["to"],
                                  "value": t["value"], "symbol": t["symbol"], "hash": t["hash"]}
                                 for t in sorted(rows, key=lambda t: -t["time"])[:10] if t["value"]]
        result["chains"][chain] = out

    result["verdict"] = "RED FLAG" if red else "no red flags in public data"
    if a.json:
        print(json.dumps(result, indent=2))
        return 1 if red else 0

    print(f"\nAML screen for {addr}\n")
    for chain, out in result["chains"].items():
        name = CHAINS[chain]["name"]
        print(f"== {name}")
        if "error" in out:
            print(f"   ERROR  {out['error']}\n")
            continue
        s = out["self"]
        sanc = {True: "SANCTIONED", False: "not sanctioned", None: "could not check"}[s["sanctioned"]]
        print(f"   sanctions    {sanc}  (Chainalysis oracle)")
        if CHAINS[chain]["freeze"]:
            checked = [sym for sym, _, _ in CHAINS[chain]["freeze"] if sym not in s["unchecked"]]
            frozen = ", ".join(s["frozen_by"]) or "none"
            print(f"   frozen by    {frozen}  (checked {', '.join(checked) or 'nothing'})")
        else:
            print("   frozen by    n/a  (stablecoins here have no on-chain freeze list)")
        if out.get("history_source") is None and out.get("history_note") and "transfers" not in out:
            print(f"   contacts     skipped: {out['history_note']}")
        elif out.get("transfers") == 0:
            print(f"   contacts     no transfers yet  ({out['history_source']})")
        elif "transfers" in out:
            since = "oldest read" if out["truncated"] else "since"
            print(f"   contacts     {out['counterparties']} addresses over {out['transfers']} transfers"
                  f", {since} {out['first_seen']}  ({out['history_source']})")
            if out.get("history_note"):
                print(f"                note: {out['history_note']}")
            if not out["flagged_counterparties"]:
                print("                none sanctioned, frozen or Tornado Cash")
            for f in out["flagged_counterparties"]:
                print(f"   !! {f['address']}  {', '.join(f['why'])}  "
                      f"({f['in']} in / {f['out']} out, last {fmt_time(f['last'])})")
        else:
            print(f"   contacts     failed: {out.get('history_note')}")
        if "exposure" in out:
            print_exposure(chain, out["exposure"])
        elif "exposure_error" in out:
            print(f"   exposure     {out['exposure_error']}")
        if "native_balance" in out:
            bal = out["native_balance"]
            gas = CHAINS[chain]["gas"]
            print(f"   gas balance  {'?' if bal is None else f'{bal:.6g}'} {gas}")
        for t in out.get("recent", []):
            arrow = "<-" if t["dir"] == "in" else "->"
            print(f"   {time.strftime('%Y-%m-%d %H:%M', time.gmtime(t['time']))}Z  {t['dir']:3} "
                  f"{t['value']:.6g} {t['symbol']}  {arrow} {t['counterparty']}")
        print()
    print(f"VERDICT: {result['verdict']}")
    print("Public-data screen only: sanctions, stablecoin freezes, Tornado Cash and public explorer")
    print("labels. Paid tools cluster and label far more wallets, so they can still rate it higher.\n")
    return 1 if red else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
