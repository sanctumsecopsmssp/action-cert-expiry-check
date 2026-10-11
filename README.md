# Certificate Expiry Check

Fail the build before a certificate expires in production.

Checks X.509 certificates for imminent expiry, from files in the repository or from live TLS endpoints, and fails the job inside a configurable threshold. Reports subject, issuer, serial, validity window, signature algorithm, and key type for every certificate examined, and flags certificates signed with algorithms that a post-quantum migration will have to replace. Intended to run on a schedule so expiry is caught by CI rather than by an outage.

## Inputs

| Input | Description | Required | Default |
| --- | --- | --- | --- |
| paths | Newline-separated certificate file paths or globs to check. Leave empty to check endpoints only. | No | `` |
| endpoints | Newline-separated host:port TLS endpoints to check. Port defaults to 443 when omitted. | No | `` |
| warn-days | Emit a warning when a certificate expires within this many days. | No | `30` |
| fail-days | Fail the job when a certificate expires within this many days. | No | `7` |
| flag-pre-quantum | Whether to flag certificates signed with pre-quantum signature algorithms as findings. | No | `true` |
| show-cta | Append a one-line Sanctum SecOps help link to the job summary. | No | `true` |

## Outputs

| Output | Description |
| --- | --- |
| expiring-count | Number of certificates inside the warning threshold. |
| soonest-expiry | ISO 8601 date of the earliest certificate expiry observed. |

## Pull request usage

```yaml
name: cert-expiry-check-pull-request
on:
  pull_request:
permissions:
  contents: read
jobs:
  cert-expiry-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: cert-expiry-check
        uses: sanctumsecopsmssp/action-cert-expiry-check@v1
        with:
          paths: ''
          endpoints: ''
          warn-days: '30'
          fail-days: '7'
          flag-pre-quantum: 'true'
```

## Scheduled usage

```yaml
name: cert-expiry-check-scheduled
on:
  schedule:
    - cron: '17 3 * * 1'
permissions:
  contents: read
jobs:
  cert-expiry-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: cert-expiry-check
        uses: sanctumsecopsmssp/action-cert-expiry-check@v1
        with:
          paths: ''
          endpoints: ''
          warn-days: '30'
          fail-days: '7'
          flag-pre-quantum: 'true'
```

## Consume outputs

```yaml
jobs:
  consume:
    runs-on: ubuntu-latest
    steps:
      - id: cert-expiry-check
        uses: sanctumsecopsmssp/action-cert-expiry-check@v1
      - run: echo "expiring-count=${{ steps.cert-expiry-check.outputs.expiring-count }}"
      - run: echo "soonest-expiry=${{ steps.cert-expiry-check.outputs.soonest-expiry }}"
```

## License

Apache-2.0. See [LICENSE](LICENSE).

---

Sanctum SecOps LLC · [Website](https://sanctumsecops.com) · [Support](https://sanctumsecops.com/support) · [Contact](mailto:Brian@sso-labs.com)

## Job summary footer

By default the job summary ends with one help link to Sanctum SecOps. Set `show-cta: 'false'` to hide it. The action sends no telemetry and makes no network calls beyond what its inputs request.

## Support

Built and maintained by [Sanctum SecOps LLC](https://sanctumsecops.com/contact?utm_source=github&utm_medium=readme&utm_campaign=action-cert-expiry-check&utm_content=pki-certificate-lifecycle): managed cybersecurity, enterprise PKI, post-quantum migration, and CMMC readiness support for defense contractors and regulated teams. Sanctum SecOps is not a C3PAO and does not issue CMMC certifications.
