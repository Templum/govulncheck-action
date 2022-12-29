# Golang Vulncheck
This a fork of [Templum/govulncheck-action](https://github.com/Templum/govulncheck-action) repository. For more information, consult with the original version.

## Background
- The original software provides functionality to perform vulnerability checks and upload the results to Github.

- The current version (v0.0.8) of the original software does not support fetching dependencies from private repositories. The executable is ran in a container, which currently does not allow injecting private SSH keys, needed to access ConnectRN Github repositories.

Forking the repository allows the following:
- Bringing this software under ConnectRN change control process
- Preserves the licensing terms from future changes