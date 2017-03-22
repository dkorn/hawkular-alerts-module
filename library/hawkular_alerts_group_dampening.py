#!/usr/bin/python


DOCUMENTATION = '''
---
module: hawkular_alerts_group_dampening
description: The hawkular_alerts_group_dampening module supports creating, updating listing and deleting Group Trigger Dampenings in Hawkular Alerts
short_description: Creating, updating listing and deleting Group Trigger Dampenings in Hawkular Alerting
requirements: [ hawkular/hawkular-client-python ]
author: Daniel Korn (@dkorn)
options:
  hawkular_api_hostname:
    description:
      - the hawkular API hostname
    default: HAWKULAR_HOSTNAME env var if set, otherwise it is required to pass it
    required: True
  hawkular_api_port:
    description:
      - the hawkular API port
    default: HAWKULAR_PORT env var if set, otherwise it is required to pass it
    required: True
  hawkular_api_auth_token:
    description:
      - the hawkular API auth token
    default: HAWKULAR_TOKEN env var if set, otherwise it is required to pass it
    required: True
  tenant:
    description:
      - the hawkular tenant
    required: True
  group_id:
    description:
      - the owning group trigger id
    required: True
  scheme:
    description:
      - the hawkular scheme
    default: 'https'
    required: False
    choices: ['https', 'http']
  cafile:
    description:
      - the path to the ca file
    default: null
    required: False
  state:
    description:
      - the state of the group dampening
      - On present, it will create the group dampening
        if it does not exist, or update it if needed
      - On absent, it will delete the group dampening,
        if it exists
    required: True
    choices: ['present', 'absent', 'list']
  dampenings:
    description:
      - A hash (dictionary) of group trigger dampening definitions to be
        created, updated or deleted.
      - The key for each dampening is its trigger mode,
        'FIRING' or 'AUTORESOLVE'
    required: False
    default: null
  verify_ssl:
    description:
      - whether SSL certificates should be verified for HTTPS requests
    required: false
    default: True
    choices: ['True', 'False']
  ca_file_path:
    description:
      - the path to a ca file
    required: false
    default: null
'''

EXAMPLES = '''
# Create group dampening
  hawkular_alerts_group_dampening:
    hawkular_api_hostname: 'hawkular-endpoint.example.com'
    port: 443
    token: '******'
    tenant: '_system'
    group_id: 'example-group-trigger'
    state: 'present'
    verify_ssl: True
    ca_file_path: /path/to/cafile.pem
    dampenings:
      FIRING:
        type: 'STRICT'
        eval_true_setting: 3
      AUTORESOLVE:
        type: 'RELAXED_COUNT'
        eval_true_setting: 2
        eval_total_setting: 4

'''

import os
import ssl
import urllib2
import hawkular.alerts


class HawkularAlertsGroupDampening(object):
    """ Hawkular Alerts object to create, update and delete group trigger dampenings in Hawkular
    """
    def __init__(self, module, tenant, hostname, port, scheme, token, context):
        self.module  = module
        self.client  = hawkular.alerts.HawkularAlertsClient(tenant, host=hostname, port=port, scheme=scheme, token=token, context=context)
        self.changed = False

    def group_trigger_exist(self, group_id):
        """
            Returns:
                True if a group trigger with the passed id exists, False otherwise
        """
        try:
            self.client.get_trigger(group_id)
        except urllib2.HTTPError as e:
            if e.code == 404:
                return False
        return True

    def get_group_dampenings(self, group_id):
        """
            Returns:
                Hash (dictionary) of the group trigger dampenings, by their trigger_mode
        """
        try:
            dampenings = self.client.list_dampenings(group_id)
        except Exception as e:
            self.module.fail_json(msg="Failed to list group trigger dampenings. Error: {error}".format(error=e))
        dampenings_dicts_list = [vars(dampening) for dampening in dampenings]
        dampenings_by_trigger_mode = {d["trigger_mode"]: d for d in dampenings_dicts_list}
        return dampenings_by_trigger_mode

    def delete_group_dampenings(self, group_id, dampenings_to_delete):
        """ Deletes group dampenings in Hawkular Alerting component

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        if not self.group_trigger_exist(group_id):
            self.module.fail_json(msg="Group trigger {group_id} doesn't exist".format(group_id=group_id))
        current_dampenings_by_trigger_mode = self.get_group_dampenings(group_id)
        messages = []
        for d in dampenings_to_delete:
            if d in current_dampenings_by_trigger_mode:
                dampening_id = current_dampenings_by_trigger_mode[d]["dampening_id"]
                try:
                    self.client.delete_group_dampening(group_id, dampening_id)
                    self.changed = True
                    messages.append("Successfully deleted group dampening {dampening_id}".format(dampening_id=dampening_id))
                except Exception as e:
                    self.module.fail_json(msg="Failed to delete group dampening. Error: {error}".format(error=e))
            else:
                messages.append("Group dampening with trigger mode {trigger_mode} doesn't exist".format(trigger_mode=d))
        return dict(
            msg=messages,
            changed=self.changed)

    def list_group_dampenings(self, group_id):
        """ Lists all dampenings in the group trigger

        Returns:
            whether or not a change took place and a short message
            describing the operation executed
        """
        if not self.group_trigger_exist(group_id):
            self.module.fail_json(msg="Group trigger {group_id} doesn't exist".format(group_id=group_id))
        group_dampenings = self.get_group_dampenings(group_id)
        return dict(
            msg="Successfully listed group dampenings",
            changed=self.changed,
            group_dampenings=group_dampenings)

    def update_required(self, desired_dampening, current_dampening):
        """ Checks if an update is required to the current dampening

            Returns:
               True, if an update is required for the dampening, False otherwise
        """
        for key in desired_dampening.keys():
            if desired_dampening[key] != current_dampening.get(key):
                return True
        return False

    def update_group_dampening(self, group_id, dampening_id, dampening):
        """ Updates a group trigger dampening in Hawkular Alerts

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        dampening_object = hawkular.alerts.Dampening(dampening)
        try:
            self.client.update_group_dampening(group_id, dampening_id, dampening_object)
        except Exception as e:
            self.module.fail_json(msg="Failed to update dampening. Error: {error}".format(error=e))
        self.changed = True

    def create_group_dampening(self, group_id, dampening):
        """ Creates a group trigger dampening in Hawkular Alerts

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        new_dampening = hawkular.alerts.Dampening(dampening)
        try:
            self.client.create_group_dampening(group_id, new_dampening)
        except Exception as e:
            self.module.fail_json(msg="Failed to create dampening. Error: {error}".format(error=e))
        self.changed = True

    def create_or_update_group_dampenings(self, group_id, dampenings):
        """ Creates or updates group trigger dampening in Hawkular Alerts

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        if not self.group_trigger_exist(group_id):
            self.module.fail(msg="Group trigger (group_id} does not exist ".format(group_id=group_id))
        messages = []
        current_dampenings_by_trigger_mode = self.get_group_dampenings(group_id)
        for trigger_mode, desired_dampening in dampenings.items():
            if trigger_mode in current_dampenings_by_trigger_mode:
                current_dampening = current_dampenings_by_trigger_mode[trigger_mode]
                dampening_id = current_dampening["dampening_id"]
                if self.update_required(desired_dampening, current_dampening):
                    self.update_group_dampening(group_id, dampening_id, desired_dampening)
                    messages.append("Successfully updated {trigger_mode} dampening {dampening_id}: {dampening}".format(trigger_mode=trigger_mode, dampening_id=dampening_id, dampening=desired_dampening))
            else:
                desired_dampening_copy = desired_dampening.copy()
                desired_dampening_copy["trigger_mode"] = trigger_mode
                self.create_group_dampening(group_id, desired_dampening_copy)
                messages.append("Successfully created {trigger_mode} dampening: {dampening}".format(trigger_mode=trigger_mode, dampening=desired_dampening_copy))
        if not messages:
            messages.append("dampening already exist, nothing to change")
        return dict(msg=messages, changed=self.changed)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hawkular_api_hostname=dict(
                default=os.environ.get('HAWKULAR_HOSTNAME'), type='str'),
            hawkular_api_port=dict(
                default=os.environ.get('HAWKULAR_PORT'), type='int'),
            hawkular_api_auth_token=dict(
                default=os.environ.get('HAWKULAR_TOKEN'), type='str', no_log=True),
            tenant=dict(required=True, type='str'),
            group_id=dict(required=True, type='str'),
            state=dict(required=True, type='str', choices=['present', 'absent', 'list']),
            scheme=dict(required=False, type='str', choices=['https', 'http'], default='https'),
            dampenings=dict(required=False, type='dict'),
            ca_file_path=dict(required=False, type='str'),
            verify_ssl=dict(required=False, type='bool', default=True),
        ),
        required_if=[
            ('state', 'present', ['dampenings']),
            ('state', 'absent', ['dampenings'])
        ],
    )

    for arg in ['hawkular_api_hostname', 'hawkular_api_port', 'hawkular_api_auth_token']:
        if module.params[arg] in (None, ''):
            module.fail_json(msg="missing required argument: {}".format(arg))
    if len(module.params["dampenings"]) > 2:
        module.fail_json(msg="A group trigger can have 2 dampenings at most")

    hostname   = module.params['hawkular_api_hostname']
    port       = module.params['hawkular_api_port']
    token      = module.params['hawkular_api_auth_token']
    tenant     = module.params['tenant']
    group_id   = module.params['group_id']
    scheme     = module.params['scheme']
    state      = module.params['state']
    dampenings = module.params['dampenings']
    verify_ssl = module.params['verify_ssl']
    ca_file    = module.params['ca_file_path']

    context = None
    if not verify_ssl:
        context = ssl._create_unverified_context()
    elif ca_file:
        context = ssl.create_default_context(cafile=ca_file)

    hawkular_alerts = HawkularAlertsGroupDampening(module, tenant, hostname, port, scheme, token, context)

    if state == "present":
        res_args = hawkular_alerts.create_or_update_group_dampenings(group_id, dampenings)
    elif state == "list":
        res_args = hawkular_alerts.list_group_dampenings(group_id)
    elif state == "absent":
        res_args = hawkular_alerts.delete_group_dampenings(group_id, dampenings)
    module.exit_json(**res_args)


# Import module bits
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
