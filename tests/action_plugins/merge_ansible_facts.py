# -*- coding: utf-8 -*-
#
# Ansible action plugin merge_ansible_facts.
# Merges saved facts with current Ansible facts on the controller and returns
# ansible_facts (saved_ansible_facts with current_ansible_facts overlaid).
#
# Copyright: (c) 2025, Linux System Roles
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):

    TRANSFERS_FILES = False

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}

        result = super(ActionModule, self).run(tmp, task_vars)
        result["changed"] = False

        current = self._task.args.get("current_ansible_facts")
        saved = self._task.args.get("saved_ansible_facts")

        if current is None:
            result["failed"] = True
            result["msg"] = "current_ansible_facts is required"
            return result
        if saved is None:
            result["failed"] = True
            result["msg"] = "saved_ansible_facts is required"
            return result

        # Template in case args were passed as raw Jinja
        current = self._templar.template(current)
        saved = self._templar.template(saved)

        if not isinstance(current, dict):
            result["failed"] = True
            result["msg"] = "current_ansible_facts must be a dict"
            return result
        if not isinstance(saved, dict):
            result["failed"] = True
            result["msg"] = "saved_ansible_facts must be a dict"
            return result

        # Merge: start with a copy of saved, overlay current (same behavior as module)
        merged = dict(saved)
        merged.update(current)
        result["ansible_facts"] = merged

        return result
