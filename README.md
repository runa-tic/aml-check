# aml-check

Free AML screen for EVM wallet addresses on Ethereum, BNB Chain and Arbitrum. It checks the
Chainalysis sanctions oracle and the USDT/USDC freeze lists, then screens every direct
counterparty for sanctions, freezes and Tornado Cash contracts. Public data only: it does not see
the private scam and darknet labels paid tools use.

    python aml_check.py 0xYourAddress --details

Contact screening needs an Etherscan key (free for Ethereum and Arbitrum) in `ETHERSCAN_API_KEY`
or `~/.config/aml-check/etherscan_key`.

## As a Claude Code plugin

    claude plugin marketplace add runa-tic/aml-check
    claude plugin install aml-check@aml-check

Then send Claude an address and it runs the check.
