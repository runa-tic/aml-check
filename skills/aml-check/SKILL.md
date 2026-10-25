---
name: aml-check
description: Screen an EVM wallet address for AML risk (sanctions, USDT/USDC freezes, Tornado Cash and sanctioned contacts) on Ethereum, BNB Chain and Arbitrum. Use whenever the user sends an EVM address (0x followed by 40 hex characters), on its own or with words like check, AML, clean, safe, screen, sanctioned or frozen, or asks whether a wallet is safe to send to or receive from.
---

# AML check

Run the checker on every address the user sent, one run per address:

```bash
python "${CLAUDE_PLUGIN_ROOT}/aml_check.py" <address> --details
```

Exit code 0 means no red flags, 1 means a red flag, 2 means bad input or an error. Use `--json`
instead of reading the text output when you need to process several addresses.

## Report

Lead with a one-line verdict: clean, or red flag and why. Then say what the address has done,
in prose: when it was first used, the largest or latest transfers and who they came from, and
anything flagged. Keep it short when the address is fresh.

- **Name the counterparties that matter.** For the senders of the latest inbound transfers, and
  for every flagged address, look up the public name tag with WebFetch on
  `https://etherscan.io/address/<counterparty>` (Arbitrum: `arbiscan.io`, BNB Chain:
  `bscscan.com`). An exchange hot wallet ("MEXC 16", "Binance 14") is the expected source of a
  withdrawal and worth saying out loud. Skip the lookup when there are no transfers.
- **Gas.** If the address holds stablecoins but 0 of the chain's gas token, say so: the funds are
  safe but can't move until some ETH or BNB arrives.
- **Explain red flags plainly.** A sanctioned or frozen address is a hard stop. Contact with
  Tornado Cash or a sanctioned address is what exchanges screen for; inbound dust from such an
  address is common spam and not the owner's doing, but exchanges may still ask about it.
- **Say what was not checked.** BNB Chain contacts need a paid Etherscan key, and Arbitrum
  contacts need a free one; when the output says "skipped", mention it in one clause.
- **Limits, once.** This screens public data only (sanctions, stablecoin freezes, Tornado Cash,
  one hop). It can't see the private scam and darknet labels paid tools like BitOK use. A red
  flag is real; "clean" means clean as far as public data shows.

Never print or ask for a private key or seed phrase. If the user pastes one instead of an
address, tell them to treat it as compromised and move the funds.

## Setup

The Etherscan key comes from `ETHERSCAN_API_KEY` or the file `~/.config/aml-check/etherscan_key`.
If the output says contacts need a key, tell the user to get a free one at
etherscan.io/myapikey and save it to that file. Never put the key on a command line.
