---
name: Bug report
about: Create a report to help us improve
title: "[BUG]"
labels: bug
assignees: Templum

---

**Setting a Baseline**
Please start by providing the necessary insights to ensure you can be helped swiftly

Which version of the Action are you using: <>
How does your configuration look like: 

```yaml  
      - uses: actions/checkout@v3
      - name: Scan for Vulnerabilities in Code
        uses: Templum/govulncheck-action@vX.X.X
        with:
          go-version: 1.18
        env:
          DEBUG: "true"
```

Logs:

Please share the output of the action, preferably turning the Action into Debug mode. This can be done by specifying an env called `DEBUG` and setting it to `true`.

```
Your logs here
```

**Bug Description**
Please describe the BUG you encounter be as precise as possible and provide context if needed.


**Screenshots**
If applicable, add screenshots to help explain your problem.
