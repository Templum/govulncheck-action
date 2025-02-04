# Golang Vulncheck

[![CI Flow](https://github.com/Templum/govulncheck-action/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Templum/govulncheck-action/actions/workflows/ci.yml) [![Release Process](https://github.com/Templum/govulncheck-action/actions/workflows/release.yml/badge.svg)](https://github.com/Templum/govulncheck-action/actions/workflows/release.yml)

This action uses govulncheck to perform a scan of the code, afterwards it will parse the output and transform it into an [Sarif](https://sarifweb.azurewebsites.net/) Report, which will be uploaded to Github using the [code-scanning API](https://docs.github.com/en/rest/code-scanning#upload-an-analysis-as-sarif-data). **Please note** this requires write-permission for `security_events`. The result should then be visible within the security-tab. By default this action won't exit with a failure if a vulnerability was found, but it can be configured this way.

## :information_source: Limitations of govulncheck :information_source:

For a full list of currently known limitations please head over to [here](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck#hdr-Limitations). Listed below are an important overview.

* Govulncheck analyzes function pointer and interface calls conservatively, which may result in false positives or inaccurate call stacks in some cases.
* Calls to functions made using package reflect are not visible to static analysis. Vulnerable code reachable only through those calls will not be reported.
* There is no support for silencing vulnerability findings.

## :books: Useful links & resources on govulncheck :books:

* Official Package Documentation: [Link](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
* Introduction Blogpost: [Link](https://go.dev/blog/vuln)

## Usage

<details>
  <summary>
  Where can I find the scan results of this action ?
  </summary>

Please be aware there will be no direct output to the console, all found vulnerabilities will be reported to Github via an Sarif Report. Therefore all findings should be located in the *Security*-Tab under the *Code Scanning*-Section.

![Locating Code Scanning](docs/locate_results.png)

![Result List](docs/results.png)

</details>

### Example Workflows

<details>
  <summary>
  This configuration uses a different version of go (1.18) scans ./... and will fail if at least one vulnerability was found.
  </summary>

  > :warning: Choosing `vulncheck-version: latest` can include breaking changes to the JSON format, which will break this action.

```yaml
name: My Workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for Vulnerabilities in Code
        uses: Templum/govulncheck-action@<version>
        with:
          go-version: 1.18
          vulncheck-version: latest
          package: ./...
          fail-on-vuln: true
```
</details>

<details>
  <summary>
  Example configuration for repository that relies on a private library.
  </summary>

> :information_source: This action for the moment works with [personal access token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) while creating one make sure it has write-read access to the dependent repositories as this is required for `$ go get`. Further following best practices create the token with the smallest possible scope.

```yaml
name: My Workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for Vulnerabilities in Code
        uses: Templum/govulncheck-action@<version>
        env:
          GH_PAT_TOKEN: ${{ secrets.PAT_TOKEN }}
          GOPRIVATE: "github.com/your-name/private-lib"

```
</details>

<details>
  <summary>
  This configuration uses most of the default values, which are specified below. However it skips the upload to Github and instead uses the upload-artifact-action to upload the result directly as build artifact.
  </summary>

```yaml
name: My Workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for Vulnerabilities in Code
        uses: Templum/govulncheck-action@<version>
        with:
          skip-upload: true
      - name: Upload Sarif Report
        uses: actions/upload-artifact@v3
        with:
          name: sarif-report
          path: govulncheck-report.sarif
```
</details>

<details>
  <summary>
  This configuration shows how to grant required permissions to the action in case you run into permission issues.
  </summary>

```yaml
name: My Workflow
on: [push, pull_request]
permissions: 
  security-events: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for Vulnerabilities in Code
        uses: Templum/govulncheck-action@<version>
```
</details>

<details>
  <summary>
  The following configuration sets the action into DEBUG Mode. Which features verbose logging and allows access to the raw govulncheck JSON report.
  </summary>

```yaml
name: My Debug Workflow
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for Vulnerabilities in Code
        uses: Templum/govulncheck-action@<version>
        with:
          skip-upload: true
        env:
          DEBUG: "true"
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: raw-report
          path: raw-report.json
```
</details>

### Inputs

| Input                            | Description                                                                                                    |
|----------------------------------|----------------------------------------------------------------------------------------------------------------|
| `go-version` _(optional)_        | Version of Go used for scanning the code, should equal *your* runtime version. Defaults to `1.21.4`            |
| `vulncheck-version` _(optional)_ | Version of govulncheck that should be used, by default `v1.0.0`                                                |
| `package` _(optional)_           | The package you want to scan, by default will be `./...`                                                       |
| `working-directory` _(optional)_ | The working directory, from where the scan should start, by default will be `github.workspace`                 |
| `github-token` _(optional)_      | Github Token to upload sarif report. **Needs** `write` permissions for `security_events`                       |
| `fail-on-vuln` _(optional)_      | This allows you to specify if the action should fail on encountering any vulnerability, by default it will not |
| `skip-upload` _(optional)_       | This flag allows you to skip the sarif upload, it will be instead written to disk as `govulncheck-report.sarif`|

> :warning: Please be aware that go-version should be a valid tag name for the [golang dockerhub image](https://hub.docker.com/_/golang/tags).

> :lock: Please be aware if the token is not specified it uses `github.token` for more details on that check [those docs](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)