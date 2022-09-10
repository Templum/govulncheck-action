# Golang Vulncheck
Performs vulnerability scan using govulncheck and afterwards uploads it as [Sarif](https://sarifweb.azurewebsites.net/) Report to Github

[![Build](https://github.com/Templum/govulncheck-action/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/Templum/govulncheck-action/actions/workflows/build.yml)

- [Vulnerability Management for Go](https://go.dev/blog/vuln)
- [govulncheck docs](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)


## Usage

Describe how to use your action here.

### Example Workflow

Please be aware that this workflow highlights all available inputs. But all inputs come with a default value.
Hence it is not required to provide any values.

```yaml
name: My Workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Running govulncheck
        uses: Templum/govulncheck-action@<version>
        with:
          package: ./...
          version: v0.0.0-20220908210932-64dbbd7bba4f
          github-token: {{ secrets.GITHUB_TOKEN }}
```

### Inputs

| Input                       | Description                                                                          |
|-----------------------------|--------------------------------------------------------------------------------------|
| `package` _(optional)_      | The package you want to scan, by default will be `./...`                             |
| `version` _(optional)_      | Version of govulncheck that should be used, by default it will be `latest`           |
| `github-token` _(optional)_ | Github Token to upload sarif report. Needs *write* permissions for `security_events` |

> Please be aware if the token is not specified it uses `github.token` for more details on that check [those docs](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
