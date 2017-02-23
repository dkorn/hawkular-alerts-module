#!/usr/bin/python


DOCUMENTATION = '''
---
module: hawkular_alerts_group_trigger
short_description: Creating, updating and deleting Group Triggers in Hawkular Alerting
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
  name:
    description:
      - the group trigger name
    default: null
    required: False
  group_id:
    description:
      - the group trigger id. This is the primary field on which one matches
      an existing trigger
    required: True
  severity:
    description:
      - the group trigger severity
    default: null
    required: False
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
      - the state of the group trigger
      - On present, it will create the group trigger
      if it does not exist, or update it if needed
      - On absent, it will delete the group trigger,
      if it exists
      - On list, it will return all triggers in the tenant
    required: True
    choices: ['present', 'absent', 'list']
  enabled:
    description:
      - whether the group trigger should be enabled or not
    required: False
    default: True
  conditions:
    description:
      - List of group trigger conditions
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
# Add example group trigger
  hawkular_alerts_group:
    hawkular_api_hostname: 'hawkular-endpoint.example.com'
    port: 443
    token: '******'
    tenant: '_system'
    group_id: 'example-group-trigger'
    name: 'Example Group Trigger'
    severity: 'high'
    state: 'present'
    verify_ssl: True
    ca_file_path: /path/to/cafile.pem
    conditions:
    - name: 'Example Condition 01'
      trigger_mode: 'FIRING'
      type: 'THRESHOLD'
      data_id: 'example_condition'
      operator: 'GT'
      threshold: 0.8
'''

import os
import ssl
import urllib2
import hawkular.alerts


class HawkularAlertsGroupTrigger(object):
    """ Hawkular Alerts object to create, update and delete group triggers in Hawkular
    """
    def __init__(self, module, tenant, hostname, port, scheme, token, context):
        self.module  = module
        self.client  = hawkular.alerts.HawkularAlertsClient(tenant, host=hostname, port=port, scheme=scheme, token=token, context=context)
        self.changed = False

    def list_triggers(self):
        """
            Returns:
                All triggers in the tenant
        """
        try:
            triggers = self.client.list_triggers()
        except Exception as e:
            self.module.fail_json(msg="Failed to list triggers. Error: {error}".format(error=e))
        triggers_dicts_list = [vars(trigger) for trigger in triggers]
        return dict(
            msg="Successfully listed triggers",
            changed=self.changed,
            triggers=triggers_dicts_list)

    def delete_group_trigger(self, group_id):
        """ Deleted a group trigger in Hawkular Alerting component

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        try:
            self.client.get_trigger(group_id)
            self.client.delete_group_trigger(group_id)
            self.changed = True
            return dict(
                msg="Successfully deleted group trigger {group_id}".format(group_id=group_id),
                changed=self.changed)
        except urllib2.HTTPError as e:
            if e.code == 404:
                return dict(
                    msg="Group trigger {group_id} doesn't exist".format(group_id=group_id),
                    changed=self.changed)
            else:
                self.module.fail_json(msg="Failed to delete group trigger. Error: {error}".format(error=e))
        except Exception as e:
            self.module.fail_json(msg="Failed to delete group trigger. Error: {error}".format(error=e))

    def conditions_update_required(self, trigger_id, desired_conditions):
        """ Returns True if an update is required in one or more of the group
            trigger conditions, False otherwise
        """
        current_conditions = self.client.get_trigger_conditions(trigger_id)

        # compare number of conditions
        if len(desired_conditions) != len(current_conditions):
            return True

        # sort conditions lists by the condition name
        current_conditions_sorted = sorted(current_conditions, key=lambda k: k.context['name'])
        desired_conditions_sorted = sorted(desired_conditions, key=lambda k: k['name'])

        for i in range(len(desired_conditions_sorted)):
            if desired_conditions_sorted[i]['name'] != current_conditions_sorted[i].context['name']:
                return True
            for key in desired_conditions_sorted[i].keys():
                actual_value = current_conditions_sorted[i].context['name'] if key == 'name' else getattr(current_conditions_sorted[i], key)
                if desired_conditions_sorted[i][key] != actual_value:
                    return True
        return False

    def required_updates(self, trigger, name, severity, enabled):
        """ Checks whether an update is required for the group trigger

            Returns:
                Empty Hash (None) - If the name, severity and enabled status passed
                                    equals the group trigger's current values
                Hash of Changes   - Changes that need to be made if the name, severity
                                    or enabled status are different than the current
                                    values of the group trigger.
        """
        updates = {}

        # `is not None` check verifies that omitted module params will not be updated
        if (name is not None and trigger.name != name):
            updates["name"] = name
        if (severity is not None and trigger.severity != severity):
            updates["severity"] = severity
        if (enabled is not None and trigger.enabled != enabled):
            updates["enabled"] = enabled
        return updates

    def set_group_trigger_conditions(self, group_id, conditions):
        """ Set the conditions for the group trigger
        """
        firing_gc = hawkular.alerts.GroupConditionsInfo()
        autoresolve_gc = hawkular.alerts.GroupConditionsInfo()
        for c in conditions:
            name = c.pop("name")
            condition = hawkular.alerts.Condition(c)
            condition.context = {'name': name}
            if condition.trigger_mode == "FIRING":
                firing_gc.addCondition(condition)
            elif condition.trigger_mode == "AUTORESOLVE":
                autoresolve_gc.addCondition(condition)
            else:
                self.module.fail_json(msg="group condition trigger_mode can be 'FIRING' or 'AUTORESOLVE', got: {trigger_mode}".format(trigger_mode=condition.trigger_mode))
        try:
            self.client.create_group_conditions(group_id, "FIRING", firing_gc)
            self.client.create_group_conditions(group_id, "AUTORESOLVE", autoresolve_gc)
        except Exception as e:
            self.module.fail_json(msg="Failed to set group trigger conditions. Error: {error}".format(error=e))
        self.changed = True

    def update_group_trigger(self, trigger, updates, conditions):
        """ Updates a group Trigger in Hawkular Alerts

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        for attr in updates:
            setattr(trigger, attr, updates[attr])
        try:
            self.client.update_group_trigger(trigger.id, trigger)
        except Exception as e:
            self.module.fail_json(msg="Failed to update group trigger. Error: {error}".format(error=e))
        if conditions is not None:
            if self.conditions_update_required(trigger.id, conditions):
                self.set_group_trigger_conditions(trigger.id, conditions)
        self.changed = True
        return dict(
            msg="Successfully updated group trigger {group_id}".format(group_id=trigger.id),
            changed=self.changed)

    def create_group_trigger(self, group_id, name, severity, enabled, conditions):
        """ Creates a group Trigger in Hawkular Alerts

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        #  create trigger object
        trigger = hawkular.alerts.Trigger()
        trigger.id = group_id
        trigger.name = name
        trigger.severity = severity
        trigger.enabled = enabled

        try:
            self.client.create_group_trigger(trigger)
        except Exception as e:
            self.module.fail_json(msg="Failed to create group trigger. Error: {error}".format(error=e))
        self.changed = True
        if conditions:
            self.set_group_trigger_conditions(group_id, conditions)
        return dict(
            msg="Successfully created group trigger {group_id}".format(group_id=group_id),
            changed=self.changed)

    def create_or_update_group_trigger(self, name, group_id, severity, enabled, conditions):
        """ Creates or updates a group trigger in Hawkular Alerts

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        try:
            gt = self.client.get_trigger(group_id)
        except urllib2.HTTPError as err:
            if err.code == 404:
                return self.create_group_trigger(group_id, name, severity, enabled, conditions)
            else:
                raise
        updates = self.required_updates(gt, name, severity, enabled)
        if not updates:
            if conditions is not None and self.conditions_update_required(group_id, conditions):
                self.set_group_trigger_conditions(group_id, conditions)
                self.changed = True
                return dict(
                    msg="Updated group trigger {group_id} conditions".format(group_id=group_id),
                    changed=self.changed)
            else:
                return dict(
                    msg="Group trigger {group_id} already exist, nothing to change.".format(group_id=group_id),
                    changed=self.changed)
        else:
            return self.update_group_trigger(gt, updates, conditions)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            hawkular_api_hostname=dict(
                default=os.environ.get('HAWKULAR_HOSTNAME'), type='str'),
            hawkular_api_port=dict(
                default=os.environ.get('HAWKULAR_PORT'), type='int'),
            hawkular_api_auth_token=dict(
                default=os.environ.get('HAWKULAR_TOKEN'), type='str'),
            tenant=dict(required=True, type='str'),
            name=dict(type='str'),
            group_id=dict(required=True, type='str'),
            severity=dict(type='str'),
            state=dict(required=True, type='str', choices=['present', 'absent', 'list']),
            scheme=dict(required=False, type='str', choices=['https', 'http'], default='https'),
            enabled=dict(required=False, type='bool', default=True),
            ca_file_path=dict(required=False, type='str'),
            verify_ssl=dict(required=False, type='bool', default=True),
            conditions=dict(required=False, type='list'),
        ),
        required_if=[
            ('state', 'present', ['name', 'severity'])
        ],
    )

    for arg in ['hawkular_api_hostname', 'hawkular_api_port', 'hawkular_api_auth_token']:
        if module.params[arg] in (None, ''):
            module.fail_json(msg="missing required argument: {}".format(arg))

    hostname   = module.params['hawkular_api_hostname']
    port       = module.params['hawkular_api_port']
    token      = module.params['hawkular_api_auth_token']
    tenant     = module.params['tenant']
    name       = module.params['name']
    group_id   = module.params['group_id']
    severity   = getattr(hawkular.alerts.Severity, module.params['severity'].upper())
    scheme     = module.params['scheme']
    state      = module.params['state']
    enabled    = module.params['enabled']
    verify_ssl = module.params['verify_ssl']
    ca_file    = module.params['ca_file_path']
    conditions = module.params['conditions']

    context = None
    if not verify_ssl:
        context = ssl._create_unverified_context()
    elif ca_file:
        context = ssl.create_default_context(cafile=ca_file)

    hawkular_alerts = HawkularAlertsGroupTrigger(module, tenant, hostname, port, scheme, token, context)

    if state == "present":
        res_args = hawkular_alerts.create_or_update_group_trigger(name, group_id, severity, enabled, conditions)
    elif state == "absent":
        res_args = hawkular_alerts.delete_group_trigger(group_id)
    elif state == "list":
        res_args = hawkular_alerts.list_triggers()
    module.exit_json(**res_args)


# Import module bits
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
