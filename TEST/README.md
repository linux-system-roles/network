TEST
----

```sh
git clone git://github.com/ansible/ansible.git --recursive
. ./ansible/hacking/env-setup

git clone git@github.com:NetworkManager/ansible-network-role.git

cd ./ansible-network-role/

cat <<EOF > ./TEST/inventory
[network-test]
v-rhel6 ansible_user=root network_iphost=196 network_mac=52:54:00:44:9f:ba
v-rhel7 ansible_user=root network_iphost=97  network_mac=52:54:00:05:f5:b3
EOF

../ansible/hacking/test-module -m ./library/network_connections.py -a 'provider=nm name=t-eth0 state=present type=ethernet' --check

ansible-playbook -i ./TEST/inventory -l '*rhel*' ./TEST/test-playbook-3.yml --verbose --check
```
