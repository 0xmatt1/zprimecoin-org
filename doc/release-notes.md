(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Notable changes
===============

Sprout to Sapling Migration Tool
--------------------------------
This release includes the addition of a tool that will enable users to migrate
shielded funds from the Sprout pool to the Sapling pool while minimizing
information leakage.

The migration can be enabled using the RPC `z_setmigration` or by including
`-migration` in the `zprime.conf` file. Unless otherwise specified funds will be
migrated to the wallet's default Sapling address; it is also possible to set the
receiving Sapling address using the `-migrationdestaddress` option in `zprime.conf`.

See [ZIP308](https://github.com/zprimecoin/zips/blob/master/zip-0308.rst) for full details.

Sprout to Sapling Migration Tool Fixes
--------------------------------------
The 2.0.5-1 release includes fixes to the Sprout to Sapling Migration Tool
found in testing. We resolved an issue which would cause the zprime daemon to
crash if calling the RPC `z_getmigrationstatus` while a wallet's migration
transactions are in the mempool.

New consensus rule: Reject blocks that violate turnstile
--------------------------------------------------------
In the 2.0.4 release the consensus rules were changed on testnet to enforce a
consensus rule which marks blocks as invalid if they would lead to a turnstile
violation in the Sprout or Shielded value pools.
**This release enforces the consensus rule change on mainnet**

The motivations and deployment details can be found in the accompanying
[ZIP draft](https://github.com/zprimecoin/zips/pull/210) and
[PR 3968](https://github.com/zprimecoin/zprime/pull/3968).

Developers can use a new experimental feature `-developersetpoolsizezero` to test
Sprout and Sapling turnstile violations. See [PR 3964](https://github.com/zprimecoin/zprime/pull/3964) for more details.


64-bit ARMv8 support
--------------------
Added ARMv8 (AArch64) support. This enables users to build zprime on even more
devices.

For information on how to build see the [User Guide](https://zprime.readthedocs.io/en/latest/rtd_pages/user_guide.html#build)

Users on the zPrime forum have reported successes with both the Pine64 Rock64Pro
and Odroid C2 which contain 4GB and 2GB of RAM respectively.

Just released, the Odroid N2 looks like a great solution with 4GB of RAM. The
newly released Jetson Nano Developer Kit from Nvidia (also 4GB of RAM) is also
worth a look. The NanoPC-T3 Plus is another option but for the simplest/best
experience choose a board with 4GB of RAM. Just make sure before purchase that
the CPU supports the 64-bit ARMv8 architecture.
