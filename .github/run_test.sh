#!/bin/bash -x

set -euo pipefail

TEST_SOURCE_DIR="/network-role"
C8S_CONTAINER_IMAGE="quay.io/linux-system-roles/c8s-network-role"
C8_CONTAINER_IMAGE="quay.io/linux-system-roles/c8-network-role"
C7_CONTAINER_IMAGE="quay.io/linux-system-roles/c7-network-role"
PODMAN_OPTS="--systemd=true --privileged"

read -r -d '' TEST_FILES << EOF || :
tests_802_1x_nm.yml
tests_bond_nm.yml
tests_auto_gateway_nm.yml
tests_bridge_nm.yml
tests_change_indication_on_repeat_run.yml
tests_dummy_nm.yml
tests_eth_dns_support_nm.yml
tests_ethtool_coalesce_nm.yml
tests_ethtool_features_nm.yml
tests_ethtool_ring_nm.yml
tests_ipv6_disabled_nm.yml
tests_ipv6_nm.yml
tests_vlan_mtu_nm.yml
tests_wireless_nm.yml
EOF

EXEC_PATH=$(dirname "$(realpath "$0")")
PROJECT_PATH=$(dirname "$(realpath "$EXEC_PATH../")")

# Default to CentOS 8
OS_TYPE=c8

while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        --os)
            OS_TYPE=$2
            shift # past argument
            shift # past value
            ;;
        *)    # unknown option
            echo "Unknown option, please try $1 --os c8s"
            exit 1
            ;;
    esac
done

case $OS_TYPE in
    "c8s")
        CONTAINER_IMAGE=$C8S_CONTAINER_IMAGE
        ;;
    "c8")
        CONTAINER_IMAGE=$C8_CONTAINER_IMAGE
        ;;
    "c7")
        CONTAINER_IMAGE=$C7_CONTAINER_IMAGE
        ;;
    *)
        echo "Unsupported OS type $OS_TYPE"
        exit 1
        ;;
esac

# shellcheck disable=SC2086
CONTAINER_ID=$(podman run -d $PODMAN_OPTS \
    -v "$PROJECT_PATH":$TEST_SOURCE_DIR $CONTAINER_IMAGE)

if [ -z "$CONTAINER_ID" ];then
    echo "Failed to start container"
    exit 1
fi

function clean_up {
    podman rm -f "$CONTAINER_ID" || true
}

if [ -z "${DEBUG:-}" ];then
    trap clean_up ERR EXIT
fi

# Ensure we are testing the latest packages and ignore upgrade failure
sudo podman exec -i "$CONTAINER_ID" /bin/bash -c  'dnf upgrade -y' || true

podman exec -i "$CONTAINER_ID" \
    /bin/bash -c  \
        'while ! systemctl is-active dbus; do sleep 1; done'

podman exec -i "$CONTAINER_ID" \
    /bin/bash -c  'sysctl -w net.ipv6.conf.all.disable_ipv6=0'

sudo podman exec -i "$CONTAINER_ID" \
        /bin/bash -c  \
                'systemctl start systemd-udevd;
        while ! systemctl is-active systemd-udevd; do sleep 1; done'


podman exec -i "$CONTAINER_ID" \
    /bin/bash -c  \
        'systemctl restart NetworkManager;
         while ! systemctl is-active NetworkManager; do sleep 1; done'

podman exec -i "$CONTAINER_ID" \
    /bin/bash -c  \
        'systemctl restart sshd;
         while ! systemctl is-active sshd; do sleep 1; done'

podman exec -i "$CONTAINER_ID" \
    /bin/bash -c  \
        'cat /dev/zero | ssh-keygen -q -N "";
         cp -v /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys'

for test_file in $TEST_FILES; do
    podman exec -i "$CONTAINER_ID" \
        /bin/bash -c  \
            "cd $TEST_SOURCE_DIR;
             env ANSIBLE_HOST_KEY_CHECKING=False \
                 ansible-playbook -i localhost, \
                 ./tests/$test_file"
done

if [ -n "${DEBUG:-}" ];then
    podman exec -it "$CONTAINER_ID" bash
    clean_up
fi
