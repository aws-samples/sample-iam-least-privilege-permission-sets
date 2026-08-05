# Third-Party Licenses

LP2PS uses the open-source components listed below, each distributed under its own license.
No copyleft dependency (GPL / LGPL / AGPL / SSPL) is present in any component, at runtime or
at build time. CI enforces this.

Measured 2026-08-05 on a clean checkout installed from public registries only
(`registry.npmjs.org`, `pypi.org`). To reproduce:

```
pip-licenses                                  # engine, backend — per virtualenv
npx license-checker --production --summary    # frontend, infra
```

Counts below exclude LP2PS's own packages (`lp2ps`, `lp2ps-api`, `lp2ps-frontend`,
`lp2ps-infra`). The two ecosystems are presented differently because their runtime closures
differ in size: the Python runtime closure is small enough to list in full, whereas for
JavaScript/TypeScript the direct dependencies are listed individually and the transitive set
is given as a license distribution.

## Runtime dependencies

### Python — engine and backend

Production closure measured in a virtualenv installed without development extras:
22 third-party packages, all permissive.

| Component | Version | License |
|---|---|---|
| boto3 | 1.43.63 | Apache-2.0 |
| botocore | 1.43.63 | Apache-2.0 |
| s3transfer | 0.19.2 | Apache-2.0 |
| pyarrow | 25.0.0 | Apache-2.0 |
| jmespath | 1.1.0 | MIT |
| PyYAML | 6.0.3 | MIT |
| pydantic | 2.13.4 | MIT |
| pydantic-core | 2.46.4 | MIT |
| annotated-types | 0.8.0 | MIT |
| annotated-doc | 0.0.5 | MIT |
| typing-inspection | 0.4.2 | MIT |
| typing-extensions | 4.16.0 | PSF-2.0 |
| fastapi | 0.141.1 | MIT |
| starlette | 1.3.1 | BSD-3-Clause |
| anyio | 4.14.2 | MIT |
| idna | 3.18 | BSD-3-Clause |
| urllib3 | 2.7.0 | MIT |
| mangum | 0.21.0 | MIT |
| Jinja2 | 3.1.6 | BSD-3-Clause |
| MarkupSafe | 3.0.3 | BSD-3-Clause |
| python-dateutil | 2.9.0.post0 | Apache-2.0 / BSD (dual-licensed) |
| six | 1.17.0 | MIT |

### JavaScript / TypeScript — frontend

Production closure: 66 third-party packages — MIT 44, Apache-2.0 13, BSD-3-Clause 6,
0BSD 2, BSD-2-Clause 1. Direct dependencies:

| Component | Version | License |
|---|---|---|
| react | 18.3.1 | MIT |
| react-dom | 18.3.1 | MIT |
| react-router-dom | 6.30.4 | MIT |
| @cloudscape-design/components | 3.0.1328 | Apache-2.0 |
| @cloudscape-design/global-styles | 1.0.62 | Apache-2.0 |
| amazon-cognito-identity-js | 6.3.20 | Apache-2.0 |

### JavaScript / TypeScript — infra (CDK)

Production closure: 27 third-party packages — MIT 12, Apache-2.0 9, ISC 4, and the three
listed under "Build- and development-time only" below. Direct dependencies:

| Component | Version | License |
|---|---|---|
| aws-cdk-lib | 2.261.0 | Apache-2.0 |
| constructs | 10.6.0 | Apache-2.0 |
| cdk-nag | 2.38.2 | Apache-2.0 |
| js-yaml | 4.3.0 | MIT |

## Build- and development-time only

Every component in this section is a build-, synthesis- or test-time dependency. **None is
part of a deployed artifact or of the browser bundle**, and each exclusion was verified
rather than assumed.

| Component | Version | License | Pulled in by | Verified not shipped |
|---|---|---|---|---|
| argparse | 2.0.1 | Python-2.0 | js-yaml | CDK synthesis only; not present in any deployed artifact |
| minimatch | 10.2.5 | BlueOak-1.0.0 | aws-cdk-lib | CDK synthesis only; not present in any deployed artifact |
| case | 1.6.3 | MIT OR GPL-3.0-or-later | aws-cdk-lib | CDK synthesis only; MIT is the elected option |
| caniuse-lite | 1.0.30001805 | CC-BY-4.0 | browserslist, via vite | Absent from `frontend/dist/` — a grep for `caniuse` in the built JS and CSS returns no match |
| certifi | 2026.7.22 | MPL-2.0 | requests, via detect-secrets / moto / pip-audit / responses | Development and test tooling only. Absent from a production-only virtualenv, so it is not distributed; used unmodified |
| regex | 2026.7.19 | Apache-2.0 AND CNRI-Python | python-hcl2 (test-only Terraform parser) | Test dependency; not deployed |

`argparse` 2.0.1 is the JavaScript package of that name, not the Python standard-library
module. `Python-2.0`, `BlueOak-1.0.0`, `MPL-2.0` and `CC-BY-4.0` are not GPL-family
licenses, and none of these components is modified or statically linked here. They are
listed because they are the only non-permissive licenses anywhere in the dependency graph,
and a reader auditing this repository should not have to discover that for themselves.

License texts are included in each package's own distribution.

## Re-measuring

The versions and counts above are a point-in-time measurement, not a permanent contract.
Re-run the two commands at the top and update this file — including the measurement date —
whenever dependency versions change, in particular after any `npm audit fix` or lockfile
refresh, since a version bump can also change a license.
