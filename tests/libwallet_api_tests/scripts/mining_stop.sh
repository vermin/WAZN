#!/bin/bash

rlwrap wazn-wallet-cli --wallet-file wallet_m --password "" --testnet --trusted-daemon --daemon-address localhost:33787  --log-file wallet_miner.log stop_mining
