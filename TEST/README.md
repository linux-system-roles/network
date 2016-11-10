TEST
----

```sh
git clone git://github.com/ansible/ansible.git --recursive
. ./ansible/hacking/env-setup

git clone git@github.com:NetworkManager/ansible-network-role.git

cd ./ansible-network-role/

cat <<EOF > ./TEST/inventory
[network-test]
v-rhel6-1 ansible_user=root
v-rhel7-b ansible_user=root
EOF

../ansible/hacking/test-module -m ./library/network_connections.py -a 'provider=nm name=t-eth0 state=present type=ethernet' --check

ansible-playbook -i ./TEST/inventory ./TEST/test-playbook.yml --verbose --check
```
