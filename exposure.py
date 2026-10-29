"""Value-weighted exposure: where an address's money came from, and where it went, a few hops out.

The direct-contact check in aml_check.py only sees the address's own counterparties. Paid tools
score *indirect* exposure too: if 40% of the funds that reached a wallet passed through a
sanctioned exchange two hops back, the wallet carries 40% sanctioned exposure even though it
never touched the exchange. This module does the same with public data.

How a trace works, for the incoming side (the outgoing side is the mirror image):
  1. Price every transfer in USD. Only native coins, wrapped natives and major stablecoins count,
     matched by contract address, so spam tokens and fake "USDT" add nothing.
  2. Split the address's inflow by sender: each sender carries its share of the USD value.
  3. A sender with a label (sanctioned, exchange, bridge ...) or that looks like a service (a
     contract, or a wallet that has sent thousands of transactions) ends the trail; its share is
     booked to that category. Exchanges and bridges pool everyone's funds, so following them
     further would only add noise.
  4. An unlabelled wallet is opened up: its own inflow before it paid us is split by sender in
     turn, and its share passes down proportionally. Repeat up to --hops deep.
  5. Whatever is left (beyond the hop limit, below 0.2%, or past the request budget) is booked
     as "untraced".
Cross-chain swaps that write both ends on-chain are the exception to step 3: an Aori order names
the sender on one chain and the recipient on the other, so the trail jumps chains there instead
of ending at the bridge.
Native coins are valued at today's price, so shares across months of history are approximate.
"""
import csv
import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import defaultdict

LABELS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "labels", "labels.csv")

# Category -> risk level, loosely following the commercial "standard" models.
RISK = {
    "sanctioned": "severe",
    "mixer": "high",
    "stolen funds": "high",
    "frozen by issuer": "high",
    "gambling": "medium",
    "exchange": "low",
    "payment service": "low",
    "bridge": "low",
    "dex": "low",
    "lending": "low",
    "smart contract": "low",
    "unnamed service": "low",
    "untraced": None,
}
# A category is a red flag once its share of traced value reaches this.
RED_FLAG_SHARE = {"severe": 0.001, "high": 0.01}

HUB_NONCE = 5000      # a wallet that has sent this many transactions is a service, not a person
MIN_WEIGHT = 0.002    # stop following trails worth less than 0.2% of the total
TOP_K = 8             # follow at most this many counterparties per wallet
NODE_MAX_TX = 300     # records per history type for a traced wallet; a full page means "service"
MAX_LOOKUPS = 40      # counterparties per hop that get on-chain classification

# Contracts whose transfers carry a known USD value: "usd" = $1, otherwise a CoinGecko id.
PRICED_TOKENS = {
    "eth": {
        "0xdac17f958d2ee523a2206206994597c13d831ec7": "usd",       # USDT
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": "usd",       # USDC
        "0x6b175474e89094c44da98b954eedeac495271d0f": "usd",       # DAI
        "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": "usd",       # FDUSD
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ethereum",  # WETH
    },
    "bsc": {
        "0x55d398326f99059ff775485246999027b3197955": "usd",       # USDT
        "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "usd",       # USDC
        "0xe9e7cea3dedca5984780bafc599bd69add087d56": "usd",       # BUSD
        "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409": "usd",       # FDUSD
        "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "binancecoin",  # WBNB
        "0x2170ed0880ac9a755fd29b2688956bd959f933f8": "ethereum",  # Binance-Peg ETH
    },
    "arb": {
        "0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9": "usd",       # USDT0
        "0xaf88d065e77c8cc2239327c5edb3a432268e5831": "usd",       # USDC
        "0xff970a61a04b1ca14834a43f5de4533ebddb5cc8": "usd",       # USDC.e
        "0xda10009cbd5d07dd0cecc66161fc93d7c9000da1": "usd",       # DAI
        "0x82af49447d8a07e3bd95bd0d56f35241523fbab1": "ethereum",  # WETH
    },
}
NATIVE_ID = {"eth": "ethereum", "bsc": "binancecoin", "arb": "ethereum"}

# Verified contract name -> category, for contracts no label set knows. Bridges and swap
# aggregators are most of what an ordinary wallet touches.
NAME_RULES = [
    ("bridge", re.compile(
        r"bridge|stargate|layerzero|\boft|wormhole|cbridge|celer|across|relay|synapse|anyswap|"
        r"multichain|orbiter|meson|symbiosis|rubic|aori|socket|lifi|debridge|allbridge|squid|axelar|"
        r"chainflip|butter|owlto|rhino|mayan|gaszip|bungee|swft|portal", re.I)),
    ("dex", re.compile(
        r"settler|router|swap|pair\b|pool|aggregat|1inch|kyber|pancake|uniswap|openocean|paraswap|"
        r"odos|dodo|curve|balancer|sushi|thena|biswap|exchangeproxy|vault", re.I)),
]

# Aori (cross-chain intent swaps). Deposit(orderId, Order) is emitted on the source chain and
# Fill(orderId, Order) on the destination; Order is (inputAmount, outputAmount, inputToken,
# outputToken, startTime, endTime, srcEid, dstEid, offerer, recipient), all static words. The
# solver pays the recipient from its own funds, so only the order links the two wallets.
AORI_DEPOSIT = "0x8e45fa612720ed3142e896a3a29c981f4ca01c25bca19c3a5c203398ee1bc3d7"
AORI_FILL = "0x7f80314442bfb82d1f9dfa4f96cbc84ae8fef158c7a93315024778ca3fc16716"
MAX_CROSS_TX = 20     # order transactions decoded per bridge contact

# LayerZero v2 endpoint ids, which Aori uses for chains.
LZ_EID = {30101: "eth", 30102: "bsc", 30110: "arb"}
LZ_NAME = {30101: "Ethereum", 30102: "BNB Chain", 30106: "Avalanche", 30109: "Polygon",
           30110: "Arbitrum", 30111: "Optimism", 30184: "Base"}

# Smart-contract wallets (Safe, ERC-4337 accounts) belong to a person: trace through them.
WALLET_NAME = re.compile(r"safe|gnosis|msca|lightaccount|kernel|simpleaccount|smartwallet|smartaccount|"
                         r"multisig|wallet", re.I)

_labels = None


def load_labels():
    """{(address, chain): (category, name)}; chain "*" applies everywhere (OFAC entries)."""
    global _labels
    if _labels is None:
        _labels = {}
        if os.path.isfile(LABELS_FILE):
            with open(LABELS_FILE, encoding="utf-8", newline="") as f:
                for r in csv.DictReader(f):
                    _labels[(r["address"], r["chain"])] = (r["category"], r["name"])
    return _labels


def label_for(chain, addr):
    labels = load_labels()
    return labels.get((addr, chain)) or labels.get((addr, "*"))


def fetch_prices():
    """{coingecko id: usd} for the native coins, or {} if CoinGecko can't be reached."""
    ids = ",".join(sorted(set(NATIVE_ID.values())))
    url = f"https://api.coingecko.com/api/v3/simple/price?ids={ids}&vs_currencies=usd"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "aml-check/1.0"})
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read())
        return {k: float(v["usd"]) for k, v in data.items() if "usd" in v}
    except Exception:
        return {}


def usd_value(chain, row, prices):
    if row["token"]:
        kind = PRICED_TOKENS[chain].get(row["token"])
        if kind is None:
            return 0.0
        return row["value"] if kind == "usd" else row["value"] * prices.get(kind, 0.0)
    return row["value"] * prices.get(NATIVE_ID[chain], 0.0)


def rpc_batch(api, chain, calls):
    """calls: list of (method, params). Returns results in order, None where a call failed."""
    rpc = api.CHAINS[chain]["rpc"]
    out = [None] * len(calls)
    for start in range(0, len(calls), 25):
        chunk = range(start, min(start + 25, len(calls)))
        body = [{"jsonrpc": "2.0", "id": i, "method": calls[i][0], "params": calls[i][1]} for i in chunk]
        try:
            resp = api.http_json(rpc, body)
            if not isinstance(resp, list):
                raise ValueError("no batch")
            for item in resp:
                out[item["id"]] = item.get("result")
        except Exception:
            for i in chunk:
                try:
                    out[i] = api.http_json(rpc, body[i - start]).get("result")
                except Exception:
                    pass
    return out


def short(addr):
    return f"{addr[:6]}…{addr[-4:]}"


def contract_name(api, chain, addr, key):
    """Verified contract name from Etherscan (the implementation's, for a proxy), or None."""
    if not key:
        return None
    base = "https://api.etherscan.io/v2/api?"
    for _ in range(2):  # the address, then its implementation if it is a proxy
        q = {"chainid": api.CHAINS[chain]["id"], "module": "contract", "action": "getsourcecode",
             "address": addr, "apikey": key}
        try:
            res = api.etherscan_get(base + urllib.parse.urlencode(q)).get("result")
        except Exception:
            return None
        time.sleep(0.25)
        if not isinstance(res, list) or not res:
            return None
        info = res[0]
        impl = (info.get("Implementation") or "").lower()
        name = info.get("ContractName") or None
        if info.get("Proxy") == "1" and impl.startswith("0x") and impl != addr:
            addr = impl
            continue
        return name
    return None


def classify(api, chain, addrs, key=None):
    """{address: (category, name) or None}. None means an ordinary wallet worth tracing further."""
    addrs = list(addrs)
    if not addrs:
        return {}
    out = {}
    for a in addrs:
        if a == "0x" + "0" * 40:
            out[a] = ("smart contract", "token mint/burn")
        else:
            out[a] = label_for(chain, a)
    todo = [a for a in addrs if out[a] is None]
    if not todo:
        return out
    for a, r in api.screen(chain, todo).items():
        if r["sanctioned"]:
            out[a] = ("sanctioned", "OFAC (Chainalysis oracle)")
        elif r["frozen_by"]:
            out[a] = ("frozen by issuer", "/".join(r["frozen_by"]))
        elif r["tornado"]:
            out[a] = ("mixer", r["tornado"])
    todo = [a for a in todo if out[a] is None]
    res = rpc_batch(api, chain, [(m, [a, "latest"]) for a in todo
                                 for m in ("eth_getCode", "eth_getTransactionCount")])
    for i, a in enumerate(todo):
        code, nonce = res[2 * i], res[2 * i + 1]
        # 0xef0100... is an EIP-7702 delegation: still a person's wallet, not a contract.
        if code and code != "0x" and not code.startswith("0xef0100"):
            name = contract_name(api, chain, a, key)
            if name and WALLET_NAME.search(name):
                continue  # a person's smart-contract wallet: leave as None so the trace goes on
            cat = next((c for c, rx in NAME_RULES if name and rx.search(name)), "smart contract")
            out[a] = (cat, f"{name} {short(a)}" if name else short(a))
        elif nonce and int(nonce, 16) >= HUB_NONCE:
            out[a] = ("unnamed service", short(a))
    return out


def edges(chain, rows, node, direction, bound, prices):
    """Group a wallet's priced transfers by counterparty:
    {other: [usd, time bound for next hop, {tx hash: [usd, time]}]}.

    Incoming: transfers into `node` no later than `bound` (the funds must arrive before they can
    be passed on). Outgoing: transfers out of `node` no earlier than `bound`.
    """
    out = {}
    for r in rows:
        if direction == "in":
            if r["to"] != node or r["from"] == node or (bound and r["time"] > bound):
                continue
            other = r["from"]
        else:
            if r["from"] != node or r["to"] == node or (bound and r["time"] < bound):
                continue
            other = r["to"]
        v = usd_value(chain, r, prices)
        if v <= 0 or not other:
            continue
        e = out.setdefault(other, [0.0, r["time"], {}])
        e[0] += v
        e[1] = max(e[1], r["time"]) if direction == "in" else min(e[1], r["time"])
        tx = e[2].setdefault(r["hash"], [0.0, r["time"]])
        tx[0] += v
    return out


def aori_order(receipt, bridge, node, direction):
    """(LayerZero eid, address) at the other end of an Aori order in this receipt, or None.

    Incoming: a Fill paying `node` on this chain; the other end is the offerer on the source
    chain. Outgoing: a Deposit by `node`; the other end is the recipient on the destination chain.
    """
    topic = AORI_FILL if direction == "in" else AORI_DEPOSIT
    for lg in (receipt or {}).get("logs") or []:
        if (lg.get("address") or "").lower() != bridge or (lg.get("topics") or [None])[0] != topic:
            continue
        d = (lg.get("data") or "0x")[2:]
        words = [d[i:i + 64] for i in range(0, len(d), 64)]
        if len(words) < 10:
            continue
        src, dst = int(words[6], 16), int(words[7], 16)
        offerer, recipient = "0x" + words[8][24:], "0x" + words[9][24:]
        if direction == "in" and recipient == node:
            return src, offerer
        if direction == "out" and offerer == node:
            return dst, recipient
    return None


def receipts(api, chain, hashes, key):
    """Transaction receipts, None where unavailable. The public Arbitrum RPC refuses receipt
    calls, so Etherscan's proxy goes first when there is a key."""
    out = [None] * len(hashes)
    if key:
        base = "https://api.etherscan.io/v2/api?"
        for i, h in enumerate(hashes):
            q = {"chainid": api.CHAINS[chain]["id"], "module": "proxy",
                 "action": "eth_getTransactionReceipt", "txhash": h, "apikey": key}
            try:
                res = api.etherscan_get(base + urllib.parse.urlencode(q)).get("result")
                out[i] = res if isinstance(res, dict) else None
            except Exception:
                pass
            time.sleep(0.25)
    todo = [i for i, r in enumerate(out) if r is None]
    if todo:
        got = rpc_batch(api, chain, [("eth_getTransactionReceipt", [hashes[i]]) for i in todo])
        for i, r in zip(todo, got):
            out[i] = r
    return out


def cross(api, chain, bridge, txs, node, direction, key):
    """Follow the order transactions `txs` ({hash: [weight, time]}) between `node` and an Aori
    contract to the other chain. Returns [(chain or None, address, weight, time, chain name)];
    weight not returned stays with the bridge."""
    hashes = sorted(txs, key=lambda h: -txs[h][0])[:MAX_CROSS_TX]
    out = []
    for h, rc in zip(hashes, receipts(api, chain, hashes, key)):
        order = aori_order(rc, bridge, node, direction)
        if not order:
            continue
        eid, other = order
        c2 = LZ_EID.get(eid)
        name = LZ_NAME.get(eid, f"LayerZero chain {eid}")
        out.append((c2 if c2 in api.CHAINS else None, other, txs[h][0], txs[h][1], name))
    return out


def trace(api, chain, target, rows, direction, key, hops, budget, prices):
    """Exposure of `target` on one side. Returns a dict with the USD total and category shares.

    Trail nodes are (chain, address): a cross-chain order moves the trail to another chain."""
    start = edges(chain, rows, target, direction, None, prices)
    total = sum(e[0] for e in start.values())
    result = {"usd": total, "categories": {}, "wallets_read": 0, "failed_reads": 0, "hops": hops,
              "crossings": []}
    if total <= 0:
        return result
    cats = defaultdict(lambda: {"direct": 0.0, "indirect": 0.0, "names": defaultdict(float)})
    crossings = defaultdict(float)

    def book(cat, name, weight, depth, at):
        c = cats[cat]
        c["direct" if depth == 1 else "indirect"] += weight
        if name:
            if at != chain:
                name = f"{name} on {api.CHAINS[at]['name']}"
            c["names"][name] += weight

    def scaled(etx, factor):
        return {h: [u * factor, t] for h, (u, t) in etx.items()}

    cache, known = {(chain, target): rows}, {}
    level = [(chain, a, v / total, 1, t, ((chain, target),), scaled(etx, 1 / total))
             for a, (v, t, etx) in start.items()]
    while level:
        # Only the counterparties that carry real weight get the on-chain lookups (oracle, code,
        # contract name); the long tail of a busy address is checked against the label file only.
        weight = defaultdict(float)
        for c, addr, w, *_ in level:
            weight[(c, addr)] += w
        heavy = sorted((k for k in weight if k not in known and weight[k] >= MIN_WEIGHT),
                       key=lambda k: -weight[k])[:MAX_LOOKUPS]
        by_chain = defaultdict(list)
        for c, a in heavy:
            by_chain[c].append(a)
        for c, addrs in by_chain.items():
            for a, lab in classify(api, c, addrs, key).items():
                known[(c, a)] = lab
        nxt = []
        for c, addr, w, depth, bound, path, txs in level:
            node = (c, addr)
            lab = known.get(node) if node in known else label_for(c, addr)
            if node not in known and not lab:
                book("untraced", None, w, depth, c)
                continue
            if lab and lab[0] == "bridge" and lab[1].startswith("Aori") and txs:
                # The order names the wallet at the other end: the trail continues there, at the
                # same depth, since the bridge only carried the funds.
                left = w
                for c2, other, wt, t, cname in cross(api, c, addr, txs, path[-1][1], direction, key):
                    left -= wt
                    if c2 is None:
                        book("bridge", f"{lab[1]} via {cname}", wt, depth, c)
                        continue
                    crossings[(c2, other)] += wt
                    nxt.append((c2, other, wt, depth, t, path + (node,), {}))
                if left > 1e-12:
                    book(lab[0], lab[1], left, depth, c)
                continue
            if lab:
                book(lab[0], lab[1], w, depth, c)
                continue
            if depth >= hops or w < MIN_WEIGHT or node in path:
                book("untraced", None, w, depth, c)
                continue
            if node not in cache:
                if result["wallets_read"] >= budget:
                    book("untraced", None, w, depth, c)
                    continue
                try:
                    got, _, note = api.history(c, addr, key, NODE_MAX_TX)
                except Exception:
                    got, note = None, "failed"
                result["wallets_read"] += 1
                if got is None:
                    result["failed_reads"] += 1
                cache[node] = got
                if got is not None and note and note.startswith("only the latest"):
                    known[node] = ("unnamed service", short(addr))   # too busy to be one person
            if known.get(node):
                book(known[node][0], known[node][1], w, depth, c)
                continue
            nb = edges(c, cache[node] or [], addr, direction, bound, prices)
            sub = sum(e[0] for e in nb.values())
            if sub <= 0:
                book("untraced", None, w, depth, c)
                continue
            ranked = sorted(nb.items(), key=lambda kv: -kv[1][0])
            followed = 0.0
            for other, (v, t, etx) in ranked[:TOP_K]:
                share = w * v / sub
                nxt.append((c, other, share, depth + 1, t, path + (node,), scaled(etx, share / v)))
                followed += v
            if sub - followed > 0:
                book("untraced", None, w * (sub - followed) / sub, depth + 1, c)
        level = nxt

    for cat, c in cats.items():
        names = sorted(c["names"].items(), key=lambda kv: -kv[1])
        result["categories"][cat] = {
            "share": c["direct"] + c["indirect"], "direct": c["direct"], "indirect": c["indirect"],
            "risk": RISK.get(cat), "names": [[n, w] for n, w in names[:3]],
        }
    result["crossings"] = [{"chain": c2, "address": a, "share": w}
                           for (c2, a), w in sorted(crossings.items(), key=lambda kv: -kv[1])]
    return result


def red_flags(exposure):
    """[(side, category, share)] for categories whose share crosses the red-flag line."""
    flags = []
    for side in ("in", "out"):
        for cat, c in exposure.get(side, {}).get("categories", {}).items():
            line = RED_FLAG_SHARE.get(c["risk"])
            if line is not None and c["share"] >= line:
                flags.append((side, cat, c["share"]))
    return flags


def run(api, chain, target, rows, key, hops, budget):
    """Both sides of the trace, or {"skipped": why} when the target is itself a service."""
    t0 = time.time()
    lab = classify(api, chain, [target], key)[target]
    if lab and lab[0] in ("smart contract", "bridge", "dex", "exchange", "lending", "payment service"):
        return {"skipped": f"the address is a {lab[0]} ({lab[1]}); exposure is traced for wallets"}
    prices = fetch_prices()
    out = {side: trace(api, chain, target, rows, side, key, hops, budget, prices) for side in ("in", "out")}
    out["priced_natives"] = bool(prices)
    out["seconds"] = round(time.time() - t0, 1)
    return out
