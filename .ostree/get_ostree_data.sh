#!/bin/bash

set -euo pipefail

role_collection_dir="${ROLE_COLLECTION_DIR:-fedora/linux_system_roles}"
ostree_dir="${OSTREE_DIR:-"$(dirname "$(realpath "$0")")"}"

if [ -z "${4:-}" ] || [ "${1:-}" = help ] || [ "${1:-}" = -h ]; then
    cat <<EOF
Usage: $0 packages [runtime|testing] DISTRO-MAJOR[.MINOR] [json|yaml|raw|toml]
The script will use the packages and roles files in $ostree_dir to
construct the list of packages needed to build the ostree image.  The script
will output the list of packages in the given format
- json is a JSON list like ["pkg1","pkg2",....,"pkgN"]
- yaml is the YAML list format
- raw is the list of packages, one per line
- toml is a list of [[packages]] elements as in https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/9/html-single/composing_installing_and_managing_rhel_for_edge_images/index#creating-an-image-builder-blueprint-for-a-rhel-for-edge-image-using-the-command-line-interface_composing-a-rhel-for-edge-image-using-image-builder-command-line
The DISTRO-MAJOR.MINOR is the same format used by Ansible for distribution e.g. CentOS-8, RedHat-8.9, etc.
EOF
    exit 1
fi
category="$1"
pkgtype="$2"
distro_ver="$3"
format="$4"
pkgtypes=("$pkgtype")
if [ "$pkgtype" = testing ]; then
    pkgtypes+=(runtime)
fi

get_rolepath() {
    local ostree_dir role rolesdir roles_parent_dir
    ostree_dir="$1"
    role="$2"
    roles_parent_dir="$(dirname "$(dirname "$ostree_dir")")"
    rolesdir="$roles_parent_dir/$role/.ostree"
    # assumes collection format
    if [ -d "$rolesdir" ]; then
        echo "$rolesdir"
        return 0
    fi
    # assumes legacy role format like linux-system-roles.$role/
    for rolesdir in "$roles_parent_dir"/*-system-roles."$role"/.ostree; do
        if [ -d "$rolesdir" ]; then
          echo "$rolesdir"
          return 0
        fi
    done
    # look elsewhere
    if [ -n "${ANSIBLE_COLLECTIONS_PATHS:-}" ]; then
        for pth in ${ANSIBLE_COLLECTIONS_PATHS//:/ }; do
            rolesdir="$pth/ansible_collections/$role_collection_dir/roles/$role/.ostree"
            if [ -d "$rolesdir" ]; then
                echo "$rolesdir"
                return 0
            fi
        done
    fi
    return 1
}

get_packages() {
    local ostree_dir pkgtype pkgfile rolefile
    ostree_dir="$1"
    for pkgtype in "${pkgtypes[@]}"; do
        for suff in "" "-$distro" "-${distro}-${major_ver}" "-${distro}-${ver}"; do
            pkgfile="$ostree_dir/packages-${pkgtype}${suff}.txt"
            if [ -f "$pkgfile" ]; then
                cat "$pkgfile"
            fi
        done
        rolefile="$ostree_dir/roles-${pkgtype}.txt"
        if [ -f "$rolefile" ]; then
            local roles role rolepath
            roles="$(cat "$rolefile")"
            for role in $roles; do
                rolepath="$(get_rolepath "$ostree_dir" "$role")"
                get_packages "$rolepath"
            done
        fi
    done | sort -u
}

format_packages_json() {
    local comma pkgs pkg
    comma=""
    pkgs="["
    while read -r pkg; do
        pkgs="${pkgs}${comma}\"${pkg}\""
        comma=,
    done
    pkgs="${pkgs}]"
    echo "$pkgs"
}

format_packages_raw() {
    cat
}

format_packages_yaml() {
    while read -r pkg; do
        echo "- $pkg"
    done
}

format_packages_toml() {
    while read -r pkg; do
        echo "[[packages]]"
        echo "name = \"$pkg\""
        echo "version = \"*\""
    done
}

distro="${distro_ver%%-*}"
ver="${distro_ver##*-}"
if [[ "$ver" =~ ^([0-9]*) ]]; then
    major_ver="${BASH_REMATCH[1]}"
else
    echo ERROR: cannot parse major version number from version "$ver"
    exit 1
fi

"get_$category" "$ostree_dir" | "format_${category}_$format"
