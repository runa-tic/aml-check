#!/usr/bin/env python3
"""Rebuild labels/labels.csv from public sources.

Sources:
  OFAC SDN list   - "Digital Currency Address" entries (ETH, USDT, USDC ...), public domain.
                    An EVM address is the same on every EVM chain, so these apply to all three.
  eth-labels      - github.com/dawsbot/eth-labels, MIT: explorer name tags scraped from
                    Etherscan, BscScan and Arbiscan.
  manual.csv      - hand-added rows (same columns as the output), kept across rebuilds.

Only the categories the exposure trace scores are kept; everything else in eth-labels
(token contracts, DAO voters, airdrop hunters ...) is dropped.

Usage: python labels/update_labels.py
"""
import csv
import io
import os
import re
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "labels.csv")
MANUAL = os.path.join(HERE, "manual.csv")

SDN_URL = "https://www.treasury.gov/ofac/downloads/sdn.csv"
ETH_LABELS_URL = "https://raw.githubusercontent.com/dawsbot/eth-labels/HEAD/data/csv/accounts.csv"

CHAIN_IDS = {"1": "eth", "56": "bsc", "42161": "arb"}

# eth-labels slug -> category. The slugs are explorer label pages, so a few are misfiled
# (e.g. "bilaxy" holds Binance deposit addresses); the name tag check below runs first.
SLUGS = {
    "sanctioned": {"ofac-sanctions-lists", "ofac-sanctioned"},
    "mixer": {"tornado-cash", "mixer", "ethereum-mixer"},
    "stolen funds": {"heist", "phish-hack", "exploit", "scam"},
    "gambling": {"gambling"},
    "payment service": {"payments", "fiat-gateway"},
    "exchange": {"exchange", "hot-wallet", "cold-wallet", "coinbase", "kraken", "bitfinex", "okx",
                 "kucoin", "mexc", "gate-io", "binance", "bitget", "bilaxy", "deribit", "cex-io",
                 "delta-exchange", "blofin-exchange", "otc"},
    "bridge": {"bridge", "stargate", "allbridge", "debridge", "multichain", "layer-2"},
    "dex": {"dex", "sushiswap", "pancakeswap", "kyberswap", "curve-finance", "curve-fi", "balancer",
            "bancor", "uniswap", "1inch", "0x-protocol", "bscswap", "burgerswap"},
    "lending": {"aave", "compound", "maker", "sky", "venus", "cream-finance", "spark"},
}
SLUG_TO_CAT = {s: cat for cat, slugs in SLUGS.items() for s in slugs}

STOLEN_TAG = re.compile(r"exploit|hack|phish|scam|rug\b|drainer|heist|stolen", re.I)
MIXER_TAG = re.compile(r"tornado|mixer", re.I)
EXCHANGE_TAG = re.compile(
    r"\b(binance|coinbase|kraken|okx|okex|bybit|kucoin|huobi|htx|gate\.io|mexc|bitget|bitfinex|"
    r"gemini|bitstamp|crypto\.com|deribit|bithumb|upbit|poloniex|bittrex|bilaxy|ascendex|bingx|"
    r"whitebit|lbank|coinex|bitmart|hitbtc|hotbit|maskex|digifinex|bitvavo|bitpanda|garantex|"
    r"grinex)\b|hot wallet|\bdep:", re.I)


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "aml-check-labels/1.0"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode("utf-8", errors="replace")


def ofac_rows():
    rows = []
    for rec in csv.reader(io.StringIO(fetch(SDN_URL))):
        if len(rec) < 12:
            continue
        for addr in re.findall(r"Digital Currency Address - \w+ (0x[0-9a-fA-F]{40})", rec[11]):
            rows.append({"address": addr.lower(), "chain": "*", "category": "sanctioned",
                         "name": rec[1].strip(), "source": "OFAC SDN"})
        # Tron addresses stay in base58 (case matters); the trace converts them when loading.
        for addr in re.findall(r"Digital Currency Address - TRX (T[1-9A-HJ-NP-Za-km-z]{33})", rec[11]):
            rows.append({"address": addr, "chain": "tron", "category": "sanctioned",
                         "name": rec[1].strip(), "source": "OFAC SDN"})
    return rows


def eth_labels_rows():
    rows = []
    for rec in csv.DictReader(io.StringIO(fetch(ETH_LABELS_URL))):
        chain = CHAIN_IDS.get(rec.get("chainId", ""))
        if not chain:
            continue
        slug = rec.get("label", "")
        tag = (rec.get("nameTag") or "").strip()
        if tag == "null":
            tag = ""
        if slug.endswith("-exploit") or STOLEN_TAG.search(tag):
            cat = "stolen funds"
        elif MIXER_TAG.search(tag):
            cat = "mixer"
        elif slug in SLUG_TO_CAT:
            cat = SLUG_TO_CAT[slug]
        elif EXCHANGE_TAG.search(tag):
            cat = "exchange"
        else:
            continue
        rows.append({"address": rec["address"].lower(), "chain": chain, "category": cat,
                     "name": tag or slug, "source": "eth-labels"})
    return rows


def main():
    rows = ofac_rows() + eth_labels_rows()
    if os.path.isfile(MANUAL):
        with open(MANUAL, encoding="utf-8", newline="") as f:
            rows += [{k: (v or "").strip() for k, v in r.items()} for r in csv.DictReader(f)]
    # One row per (address, chain); later sources win, so manual.csv overrides the rest.
    merged = {}
    for r in rows:
        merged[(r["address"].lower(), r["chain"])] = r
    with open(OUT, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["address", "chain", "category", "name", "source"])
        w.writeheader()
        for key in sorted(merged):
            w.writerow(merged[key])
    counts = {}
    for r in merged.values():
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    print(f"wrote {len(merged)} labels to {OUT}")
    for cat, n in sorted(counts.items(), key=lambda x: -x[1]):
        print(f"  {n:6}  {cat}")


if __name__ == "__main__":
    main()
