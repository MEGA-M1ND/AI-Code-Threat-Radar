# Reporting privately

Two different things get reported here. They go to the same place.

**An incident you do not want to file in the open.** An unpublished compromise, something still being coordinated with a vendor, or a case where filing a public issue would tip off the person responsible. Send it privately and it will be held until it can be published, or until you say it can.

**A problem with RADAR itself.** A wrong indicator that is causing false positives in a downstream tool, an entry that names something legitimate, or a flaw in the build or validation scripts.

## How

Use [GitHub private vulnerability reporting](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/security/advisories/new) on this repository. It is private to the maintainers, it keeps the thread in one place, and it does not require sharing an email address.

If you would rather not use GitHub, open a public issue saying only that you have something to report and asking for a contact — no detail — and a private channel will be arranged.

## What to include

- What the artifact is, with its exact name.
- The primary source, if one exists yet.
- Whether the vendor or registry has been told, and whether there is an embargo date.
- What you want: publication now, publication on a date, or a heads-up with no entry.

## What happens

- Acknowledgement within three working days.
- If you are reporting a wrong indicator in an existing entry, it is verified and corrected as soon as it is proven. A false positive in a downstream guard is treated as an outage, not as a backlog item.
- If you are reporting an embargoed incident, nothing is published before the date you give.
- Credit in the entry's sources if you want it, and none if you do not.

## Out of scope

RADAR is static JSON files, a JSON Schema and two Python scripts published through GitHub releases. There is no server, no database and no user data. Reports about the security of infrastructure RADAR does not run belong with whoever runs it.
