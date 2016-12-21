#!/usr/bin/python


DOCUMENTATION = '''
---
module: hawkular_alerts_group_trigger
short_description: Creating and deleting Group Triggers in Hawkular Alerting
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
      if it does not exist
      - On absent, it will delete the group trigger,
      if it exists
    required: True
    choices: ['present', 'absent']
  enabled:
    description:
      - whether the group trigger should be enabled or not
    required: False
    default: True
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
'''

import urllib2
import hawkular.alerts

# TODO: remove once the ssl cert verification is checked
import os
import ssl


class HawkularAlertsGroupTrigger(object):
    """ Hawkular Alerts object to create and delete group triggers in Hawkular
    """
    def __init__(self, module, tenant, hostname, port, scheme, token, context):
        self.module  = module
        self.client  = hawkular.alerts.HawkularAlertsClient(tenant, host=hostname, port=port, scheme=scheme, token=token, context=context)
        self.changed = False

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

    def create_group_trigger(self, name, group_id, severity, enabled):
        """ Creates a group trigger in Hawkular Alerting component

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        try:
            self.client.get_trigger(group_id)
            return dict(
                msg="Group trigger {group_id} already exist".format(group_id=group_id),
                changed=self.changed)
        except urllib2.HTTPError as err:
            if err.code == 404:
                try:
                    #  create trigger object
                    trigger = hawkular.alerts.Trigger()
                    trigger.id = group_id
                    trigger.name = name
                    trigger.severity = getattr(hawkular.alerts.Severity, severity.upper())
                    trigger.enabled = enabled

                    self.client.create_group_trigger(trigger)
                    self.changed = True
                    return dict(
                        msg="Successfully created group trigger {group_id}".format(group_id=group_id),
                        changed=self.changed)
                except Exception as e:
                    self.module.fail_json(msg="Failed to create group trigger. Error: {error}".format(error=e))
            else:
                raise


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
            state=dict(required=True, type='str', choices=['present', 'absent']),
            scheme=dict(required=False, type='str', choices=['https', 'http'], default='https'),
            enabled=dict(required=False, type='bool', default=True),
        ),
        required_if=[
            ('state', 'present', ['name', 'severity'])
        ],
    )

    for arg in ['hawkular_api_hostname', 'hawkular_api_port', 'hawkular_api_auth_token']:
        if module.params[arg] in (None, ''):
            module.fail_json(msg="missing required argument: {}".format(arg))

    hostname = module.params['hawkular_api_hostname']
    port     = module.params['hawkular_api_port']
    token    = module.params['hawkular_api_auth_token']
    tenant   = module.params['tenant']
    name     = module.params['name']
    group_id = module.params['group_id']
    severity = module.params['severity']
    scheme   = module.params['scheme']
    state    = module.params['state']
    enabled  = module.params['enabled']

    # TODO: remove once the ssl cert verification is checked
    context = ssl._create_unverified_context()

    hawkular_alerts = HawkularAlertsGroupTrigger(module, tenant, hostname, port, scheme, token, context)

    if state == "present":
        res_args = hawkular_alerts.create_group_trigger(name, group_id, severity, enabled)
    else:
        res_args = hawkular_alerts.delete_group_trigger(group_id)
    module.exit_json(**res_args)


# Import module bits
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
