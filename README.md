# callwall — build a call allowlist from ABIs and enforce it offline

**callwall** helps teams prevent “mystery calls” from slipping into deployments
and multisig batches. Point it at ABIs to mint a minimal **policy** (selectors +
rules like `value=0`), then verify raw transactions or calldatas against that
policy — no RPC, no internet.

## Key features
- **Build policy** from ABI files (array form or Etherscan-style JSON).
- **Verify** raw tx hex **or** bare calldata against the policy.
- Enforce a default **`value_wei` rule** (e.g., `0` for all calls by default).
- Heuristically flag risky token permissions without ABIs:
  - `approve(address,uint256)` with **MAX** amount (`2^256-1`)
  - `setApprovalForAll(address,bool)` with **true**
- Outputs **JSON reports** and a tiny **SVG badge** (`PASS/FAIL`).

## Install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
