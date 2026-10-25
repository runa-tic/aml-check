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

VERDICT: no red flags in public data
```

Exit code 0 means no red flags, 1 means a red flag, 2 means bad input or an error. `--json`
prints the full result for scripts, and `--chains eth,arb` limits the run.

## Requirements

Python 3.8 or later, standard library only. Sanctions and freeze checks use public RPC
endpoints and need no account.

The contact scan needs transaction history from Etherscan's API. A
[free key](https://etherscan.io/myapikey) covers Ethereum and Arbitrum; BNB Chain needs a paid
plan, since Etherscan removed it from the free tier in 2025. Without a key, Ethereum falls back
to Blockscout's keyless API, which allows about three scans an hour. Put the key in
`ETHERSCAN_API_KEY` or in `~/.config/aml-check/etherscan_key`.

## As a Claude Code plugin

```
claude plugin marketplace add runa-tic/aml-check
claude plugin install aml-check@aml-check
```

Then paste an address into Claude Code. The bundled skill runs the screen, names the
counterparties that matter (an exchange hot wallet, say), and flags a wallet with no gas.

## Limits

It looks one hop out and only at public data. It can't see the private labels for scams,
darknet markets and high-risk services that commercial screening uses, so an exchange's own
check may rate an address differently. A red flag here is real; a clean result means clean as
far as public data shows. This is a screening aid, not legal or compliance advice.

## License

MIT
