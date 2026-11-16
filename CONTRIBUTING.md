# Contributing

Everpool is at the stage where review matters most. Useful contributions:

- **Attacks.** A way to capture, censor, stall or drain a pool, or to make
  honest nodes spend more than the budgets in section 11 allow. Please include
  the scenario step by step and what it costs the attacker.
- **Simplifications.** A mechanism that does the same job with less code or
  fewer messages.
- **Numbers.** A parameter, bound or cost estimate that looks wrong.
- **Adoption.** If you maintain a chain and want Everpool, open an issue with
  your chain's details (see [ADOPTING.md](ADOPTING.md)).

How to contribute:

1. Open an issue first for anything beyond a typo, so the discussion happens
   before the work.
2. Changes to [SPEC.md](SPEC.md) are made in the reference implementation's
   `docs/pool-registry.md` (https://github.com/bitflash-network/bitflash) and
   mirrored here, so the two never disagree. A pull request here is welcome
   and will be carried over.
3. Write in plain English. Every rule should say what it protects against.

Security issues that could harm a running network: please report them
privately through GitHub's security advisories on this repository instead of
a public issue.

All contributions are under the MIT license.
