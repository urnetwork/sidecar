# Disclosure fixtures

Test data for CTRUST's disclosure registry (DESIGN-COMPUTE §2.8; `disclosure_registry.go`). Nothing here ships: a device
reads disclosure texts only from the newest compute policy it verified (§5.4), which ATTEST's pipeline signs.

`disclosures.json` is a fixture `disclosures` line in the policy's format (`ComputePolicyDisclosure`):

- Its English texts are DESIGN-COMPUTE.md's version 1, each fence's wrapped lines joined with one space:
  `inference:local`, `inference:chutes`, `inference:engy` and `inference:saygm` (§2.8); `enclave:hippius`,
  `enclave:lium` and `enclave:cathedral`, §2.8's one enclave form filled with each provider's name and its `<inside>`
  line, without the line's closing period, since it fills the middle of a sentence; `search:parallel` (§21.6), whose
  summary is the one-line summary §21.6's To the UI row gives; `connect:google` and `connect:microsoft`, §25.12's form
  filled with the service's name and its `<revocation>` line, its first letter raised to a capital since it opens a
  list item, and `connect:custom` (below); `listeners:publish` (§26.6), `approvals:auto` (§27.11) and
  `support:urnetwork` (§28.13).
- `support:urnetwork`'s `<retention>` holds a test value, `30 days`, not the words of any agreement: a policy's text
  takes them from the policy's support line, which the agreement with the triage model's provider sets (§28.13).
- `connect:custom` is §25.12's form with `<service>` worded generically, as the owner's answer to question
  `ctrust-m11-01-connect-custom-text` gives it (QD-1440): "your <service> account" reads "your account at a service you
  added yourself" and every other `<service>` "that service", a list item's first letter raised to a capital, with its
  own `<revocation>` line. The signed policy's text is its authors' wording, reviewed as any text is.
- `inference:local` carries one test translation, German (`de`), for the locale tests alone. No second person read
  it against the English, as a translation in a signed policy must be (§2.8).
- Each entry is version 1, revision 0, a grace of 14 days from 2026-12-01T00:00:00Z.

`TestComputeDisclosureTextsVersion1` holds the English texts to the design byte for byte. Run it with
`SIDECAR_REGENERATE_DISCLOSURE_FIXTURE=1` to write them again from the design, keeping each entry's version, revision,
grace, instant and translations.
