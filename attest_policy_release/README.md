# The release's copy of the compute policy

Each `ur` release carries the compute policy current at its build (DESIGN-COMPUTE §5.4's Distribution), embedded
from this directory by `attest_policy_release.go`. `sidecarctl compute policy publish` (ATTEST-M12-02) writes it here
before a release, beside the serving tree's copy:

- `compute-policy.json` and `compute-policy.json.sig`, the production policy and its SSHSIG, in a production build;
- `compute-policy-staging.json` and `compute-policy-staging.json.sig` in a staging or CI build
  (`sidecar_compute_staging`).

A source build holds no copy: only this file. A device then starts from no policy until it fetches one, and a device
never takes a policy older than its release's copy.
