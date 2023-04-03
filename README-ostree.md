# rpm-ostree

The role supports running on [rpm-ostree](https://coreos.github.io/rpm-ostree/)
systems. The primary issue is that the `/usr` filesystem is read-only, and the
role cannot install packages. Instead, it will just verify that the necessary
packages and any other `/usr` files are pre-installed. The role will change the
package manager to one that is compatible with `rpm-ostree` systems.

## Building

To build an ostree image for a particular operating system distribution and
version, use the script `.ostree/get_ostree_data.sh` to get the list of
packages. If the role uses other system roles, then the script will include the
packages for the other roles in the list it outputs.  The list of packages will
be sorted in alphanumeric order.

Usage:

```bash
.ostree/get_ostree_data.sh packages runtime DISTRO-VERSION FORMAT
```

`DISTRO-VERSION` is in the format that Ansible uses for `ansible_distribution`
and `ansible_distribution_version` - for example, `Fedora-38`, `CentOS-8`,
`RedHat-9.4`

`FORMAT` is one of `toml`, `json`, `yaml`, `raw`

* `toml` - each package in a TOML `[[packages]]` element

```toml
[[packages]]
name = "package-a"
version = "*"
[[packages]]
name = "package-b"
version = "*"
...
```

* `yaml` - a YAML list of packages

```yaml
- package-a
- package-b
...
```

* `json` - a JSON list of packages

```json
["package-a","package-b",...]
```

* `raw` - a plain text list of packages, one per line

```bash
package-a
package-b
...
```

What format you choose depends on which image builder you are using.  For
example, if you are using something based on
[osbuild-composer](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/composing_installing_and_managing_rhel_for_edge_images/index#creating-an-image-builder-blueprint-for-a-rhel-for-edge-image-using-the-command-line-interface_composing-a-rhel-for-edge-image-using-image-builder-command-line),
you will probably want to use the `toml` output format.
