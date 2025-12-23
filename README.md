## How to run this Demo

### Setup the env variables

`workload/secrets/env`:


```
PRIVATE_KEY: must be provided for sending tx on chain
SP1_PRIVATE_KEY: Optional, provide it if you want to try SP1 zkProof
SEPOLIA_RPC: Optional, defaults to https://1rpc.io/sepolia
```

`workload/docker-compose.yml`:


```
AUTH_CONTRACT_ADDR: Optional, place the contract address here if you have deployed the MockCVMExample.sol on Sepolia and want to test it.
```


### Update the workload

- Replace the `cvm-base-image/workload/` folder with the `workload/` folder in this repo


### Deploy and check logs

```bash
# Deploy
./cvm-cli deploy-gcp --vm_name onchain-test --add-workload

# Check logs
./cvm-cli get-logs gcp onchain-test
```