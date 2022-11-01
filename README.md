# Golang Vulncheck

[![CI Flow](https://github.com/Templum/govulncheck-action/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Templum/govulncheck-action/actions/workflows/ci.yml) [![Release Process](https://github.com/Templum/govulncheck-action/actions/workflows/release.yml/badge.svg)](https://github.com/Templum/govulncheck-action/actions/workflows/release.yml)

This action uses govulncheck to perform a scan of the code, afterwards it will parse the output and transform it into an [Sarif](https://sarifweb.azurewebsites.net/) Report, which will be uploaded to Github using the [code-scanning API](https://docs.github.com/en/rest/code-scanning#upload-an-analysis-as-sarif-data). **Please note** this requires write-permission for `security_events`. The result should then be visible within the security-tab. By default this action won't exit with a failure if a vulnerability was found, but it can be configured this way.

## :information_source: Limitations of govulncheck :information_source:

For a full list of currently known limitations please head over to [here](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck#hdr-Limitations). Listed below are an important overview.

* Govulncheck only reads binaries compiled with Go 1.18 and later.
* Govulncheck only reports vulnerabilities that apply to the current Go build system and configuration (GOOS/GOARCH settings).

## :books: Useful links & resources on govulncheck :books:

* Official Package Documentation: [Link](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
* Introduction Blogpost: [Link](https://go.dev/blog/vuln)

## Usage

### Example Workflow

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
          go-version: 1.18
          vulncheck-version: latest
          package: ./...
          github-token: ${{ secrets.GITHUB_TOKEN }}
          fail-on-vuln: true
```

### Inputs

| Input                            | Description                                                                                                    |
|----------------------------------|----------------------------------------------------------------------------------------------------------------|
| `go-version` _(optional)_        | Version of Go used for scanning the code, should equal *your* runtime version. Defaults to `1.19`              |
| `vulncheck-version` _(optional)_ | Version of govulncheck that should be used, by default `latest`                                                |
| `package` _(optional)_           | The package you want to scan, by default will be `./...`                                                       |
| `github-token` _(optional)_      | Github Token to upload sarif report. **Needs** `write` permissions for `security_events`                       |
| `fail-on-vuln` _(optional)_      | This allows you to specify if the action should fail on encountering any vulnerability, by default it will not |

> :warning: Please be aware that go-version should be a valid tag name for the [golang dockerhub image](https://hub.docker.com/_/golang/tags).

> :lock: Please be aware if the token is not specified it uses `github.token` for more details on that check [those docs](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)
