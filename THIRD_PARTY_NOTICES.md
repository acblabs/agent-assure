# Third-Party Notices

## MITRE ATLAS data

`mappings/mitre_atlas_2026_06_catalog.yaml` contains a compact validation
catalog derived from the MITRE ATLAS `mitre-atlas/atlas-data` project. The
redistributed catalog selects and reformats the stable tactic and technique
identifiers and names from the pinned ATLAS 2026.06 release; it is not an
unmodified copy of the upstream source files.

Pinned upstream provenance:

- Repository: <https://github.com/mitre-atlas/atlas-data>
- Release tag: `v2026.06`
- Release commit: `651dad90d3c007e797c89356fa1f4d8732f90c8d`
- Release asset: <https://github.com/mitre-atlas/atlas-data/releases/download/v2026.06/ATLAS-2026.06.yaml>
- Release asset SHA-256: `b771de8b1489564b2838a709c7429849a9575dbd94073928817fe1a21661e70a`
- Release announcement inventory: 16 tactics, 104 techniques, and 69
  sub-techniques
- Authenticated asset inventory: 16 tactics, 103 base techniques, and 70
  sub-techniques (173 technique IDs in the compact catalog). The split differs
  by one from the release announcement; the asset count is the validation pin.

Copyright 2021-2026 MITRE

The upstream data is licensed under the Apache License, Version 2.0. The exact
upstream license notice and complete Apache License 2.0 terms are reproduced in
`third_party/mitre-atlas-atlas-data/LICENSE`.

The upstream README carries this release statement:

> Copyright 2021-2026 The MITRE Corporation. ALL RIGHTS RESERVED. Approved for Public
> Release; Distribution Unlimited. Public Release Case Numbers 21-2363,
> 26-1162.

MITRE and MITRE ATLAS are names of their respective owner. Redistribution of
the catalog does not imply endorsement of Agent Assure by MITRE.
