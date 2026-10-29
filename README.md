# aml-check

A free AML screen for EVM wallet addresses on Ethereum, BNB Chain and Arbitrum. Paid tools
score an address against private databases; this one answers the questions that public data
can answer, and says plainly where it stops.

For each chain it checks:

1. **Sanctions:** the [Chainalysis sanctions oracle](https://go.chainalysis.com/chainalysis-oracle-docs.html),
   an on-chain contract that mirrors the OFAC SDN list and is free to call.
2. **Stablecoin freezes:** whether Tether (USDT, USDT0) or Circle (USDC) has blacklisted the
   address, read straight from the token contracts. Binance-Peg stablecoins on BNB Chain have
   no on-chain freeze list.
3. **Contacts:** every address it has sent to or received from, screened for sanctions, freezes
   and Tornado Cash contracts. Tornado Cash was delisted by OFAC in 2025, so the oracle no longer
   flags it, but exchanges still treat contact with it as high risk.
4. **Exposure:** where the address's money came from and where it went, up to four wallets
   away, as shares of its USD value. This is what paid tools call indirect exposure: a wallet
   that never touched a sanctioned exchange still carries its risk if a third of its funds
   passed through one two hops back. Each trail ends at the first wallet that carries a label
   (sanctioned, mixer, stolen funds, exchange, bridge, DEX ...) or looks like a service (a
   contract, or a wallet that has sent thousands of transactions). Unlabelled contracts are
   named from their verified source code, so a bridge or swap aggregator shows by name.
   Aori cross-chain swaps are followed instead of ending the trail: the
   order on-chain names the sender on one chain and the recipient on the other, so the trace
   jumps to that wallet and carries on there.

```
$ python aml_check.py 0x... --details

== Ethereum
   sanctions    not sanctioned  (Chainalysis oracle)
   frozen by    none  (checked USDT, USDC)
   contacts     2 addresses over 3 transfers, since 2026-01-14  (Etherscan)
                none sanctioned, frozen or Tornado Cash
   gas balance  0.0042 ETH
   2026-02-03 09:12Z  out 180 USDC  -> 0x7d1e…c43b
   2026-01-14 16:40Z  in  250 USDC  <- 0x3f5c…e1a2
   exposure     in $250 / out $180, traced 4 hops, 3 wallets read, 21.4s
                  total     in    out  category          risk     how
                  58.1% 100.0%      -  exchange          low      indirect
                                         Binance: Hot Wallet 20
                  41.9%      - 100.0%  dex               low      direct
                                         RouterV2 0x91c2…7a0e

VERDICT: no red flags in public data
```

Exit code 0 means no red flags, 1 means a red flag, 2 means bad input or an error. `--json`
prints the full result for scripts, and `--chains eth,arb` limits the run. `--hops` sets how
far the exposure trace goes (0 turns it off) and `--budget` caps how many wallet histories it
reads per chain and direction.

Only transfers of the native coin, its wrapped form and major stablecoins (matched by contract
address, so a fake "USDT" counts for nothing) carry value in the trace. Native coins are valued
at today's CoinGecko price.

## Requirements

Python 3.8 or later, standard library only. Sanctions and freeze checks use public RPC
endpoints and need no account.

The contact scan needs transaction history from Etherscan's API. A
[free key](https://etherscan.io/myapikey) covers Ethereum and Arbitrum; BNB Chain needs a paid
plan, since Etherscan removed it from the free tier in 2025; the key is tried as is, and BNB
Chain is skipped if Etherscan refuses it. Without a key, Ethereum falls back
to Blockscout's keyless API, which allows about three scans an hour. Put the key in
`ETHERSCAN_API_KEY` or in `~/.config/aml-check/etherscan_key`.

## Labels

`labels/labels.csv` is built by `python labels/update_labels.py` from two public sources: the
crypto addresses on the OFAC SDN list, and [eth-labels](https://github.com/dawsbot/eth-labels)
(MIT), which collects explorer name tags. Rows in `labels/manual.csv` are added on top and win
over both. Rebuild it now and then; the explorers add tags faster than this repo is updated.

## As a Claude Code plugin

```
claude plugin marketplace add runa-tic/aml-check
claude plugin install aml-check@aml-check
```

Then paste an address into Claude Code. The bundled skill runs the screen, names the
counterparties that matter (an exchange hot wallet, say), and flags a wallet with no gas.

## Limits

It sees only public data. The trace can follow money to a busy wallet and say "unnamed
service", but naming it takes the clustered labels commercial tools keep for exchanges, scams
and darknet markets, so an exchange's own check may rate an address higher. A red flag here is real; a clean result means clean as
far as public data shows. This is a screening aid, not legal or compliance advice.

## License

MIT
