# woke-action

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/get-woke/woke-action?logo=github&sort=semver)](https://github.com/get-woke/woke-action/releases)

Woke GitHub Actions allow you to execute [`woke`](https://github.com/get-woke/woke) command within GitHub Actions.

The output of the actions can be viewed from the Actions tab in the main repository view.

## Usage

The most common usage is to run `woke` on a file/directory. This workflow can be configured by adding the following content to the GitHub Actions workflow YAML file (ie in `.github/workflows/woke.yaml`).

```yaml
name: woke
on:
  - pull_request
jobs:
  woke:
    name: woke
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v2

      - name: woke
        uses: get-woke/woke-action@v0
        with:
          # Cause the check to fail on any broke rules
          fail-on-error: true
```

## Inputs

Inputs to configure the `woke` GitHub Actions.

| Input            | Default               | Description                                                                                       |
|------------------|-----------------------|---------------------------------------------------------------------------------------------------|
| `woke-args`      | `.`                   | (Optional) Additional flags to run woke with (see <https://github.com/get-woke/woke#usage>) |
| `woke-version`   | latest                | (Optional) Release version of `woke` (defaults to latest version)                                 |
| `fail-on-error`  | `false`               | (Optional) Fail the GitHub Actions check for any failures.                                        |
| `workdir`        | `.`                   | (Optional) Run `woke` this working directory relative to the root directory.                      |
| `github-token`   | `${{ github.token }}` | (Optional) Custom GitHub Access token (ie `${{ secrets.MY_CUSTOM_TOKEN }}`).                      |

## License

This application is licensed under the MIT License, you may obtain a copy of it
[here](https://github.com/get-woke/woke-action/blob/main/LICENSE).

## Only Changed Files

If you're interested in only running `woke` against files that have changed in a PR,
consider something like [Get All Changed Files Action](https://github.com/marketplace/actions/get-all-changed-files). With this, you can add a workflow that looks like:

```yaml

name: 'woke'
on:
  - pull_request
jobs:
  woke:
    name: 'woke'
    runs-on: ubuntu-latest
    steps:
      - name: 'Checkout'
        uses: actions/checkout@v2

      - uses: jitterbit/get-changed-files@v1
        id: files

      - name: 'woke'
        uses: get-woke/woke-action@v0
        with:
          # Cause the check to fail on any broke rules
          fail-on-error: true
          # See https://github.com/marketplace/actions/get-all-changed-files
          # for more options
          woke-args: ${{ steps.files.outputs.added_modified }}
```
