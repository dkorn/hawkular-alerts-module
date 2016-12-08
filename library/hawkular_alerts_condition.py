#!/usr/bin/python


DOCUMENTATION = '''
---
module: hawkular_alerts_group
short_description: Creating Group Triggers in Hawkular Alerting
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
    default: null
    required: True
  group_id:
    description:
      - the group trigger id
    default: null
    required: True
  trigger_mode:
    description:
      - the condition trigger mode
    default: null
    required: True
  type:
    description:
      - the condition type
    default: null
    required: True
  data_id:
    description:
      - the condition data id
    default: null
    required: True
  operator:
    description:
      - the condition operator
    default: null
    required: True
  data:
    description:
      - the condition data, determind by the condition type
    default: null
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
      - the state of the user
      - On present, it will create the group trigger
      if it does not exist
    required: True
    choices: ['present', 'absent']
'''

EXAMPLES = '''
# Add example group condition
  hawkular_alerts_group:
    hawkular_api_hostname: 'hawkular-endpoint.example.com'
    port: 443
    token: '******'
    tenant: '_system'
    group_id: 'example-group-trigger'
    trigger_mode: 'FIRING'
    type: 'THRESHOLD'
    data_id: 'test_condition'
    operator: 'GT'
    data: 0.8
    state: 'present'
'''

import urllib2
import hawkular.alerts

# TODO: remove once the ssl cert verification is checked
import os


class HawkularAlertsGroupCondition(object):
    """ Hawkular Alerts object to create group conditions in Hawkular
    """
    #  verify 'RATE' should not be included in the following list
    numeric_types = ['THRESHOLD', 'COMPARE', 'RANGE']

    def __init__(self, module, tenant, hostname, port, scheme, token, context):
        self.module  = module
        self.client  = hawkular.alerts.HawkularAlertsClient(tenant, host=hostname, port=port, scheme=scheme, token=token, context=context)
        self.changed = False

    def create_group_condition(self, group_id, trigger_mode, condition_type, data_id, operator, data):
        """ Creates a group condition in Hawkular Alerting component

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        try:
            #  create condition object
            condition = hawkular.alerts.Condition()
            condition.trigger_mode = getattr(hawkular.alerts.TriggerMode, trigger_mode.upper())
            condition.type = getattr(hawkular.alerts.ConditionType, condition_type.upper())
            condition.data_id = data_id
            condition.operator = getattr(hawkular.alerts.Operator, operator.upper())

            if condition_type.upper() in HawkularAlertsGroupCondition.numeric_types:
                data = float(data)

            setattr(condition, condition_type.lower(), data)

            #  create group condition object
            group_condition = hawkular.alerts.GroupConditionsInfo()
            group_condition.addCondition(condition)

            import pdb
            tty = open('/dev/tty','r+')
            mypdb=pdb.Pdb(stdin=tty, stdout=tty)
            mypdb.set_trace()

            result = self.client.create_group_conditions(group_id, trigger_mode, group_condition)
            self.changed = True
            return dict(
                msg="Successfully created group condition",
                changed=self.changed)
        except Exception as e:
            self.module.fail_json(msg="Failed to create group condition. Error: {error}".format(error=e))


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
            group_id=dict(required=True, type='str'),
            trigger_mode=dict(required=True, type='str'),
            type=dict(required=True, type='str'),
            data_id=dict(required=True, type='str'),
            operator=dict(required=True, type='str'),
            data=dict(required=True),
            state=dict(required=True, type='str', choices=['present', 'absent']),
            scheme=dict(required=False, type='str', choices=['https', 'http'], default='https'),
        ),
    )

    for arg in ['hawkular_api_hostname', 'hawkular_api_port', 'hawkular_api_auth_token']:
        if module.params[arg] in (None, ''):
            module.fail_json(msg="missing required argument: {}".format(arg))

    hostname     = module.params['hawkular_api_hostname']
    port         = module.params['hawkular_api_port']
    token        = module.params['hawkular_api_auth_token']
    tenant       = module.params['tenant']
    group_id     = module.params['group_id']
    trigger_mode = module.params['trigger_mode']
    type         = module.params['type']
    data_id      = module.params['data_id']
    operator     = module.params['operator']
    data         = module.params['data']
    scheme       = module.params['scheme']
    state        = module.params['state']

    # TODO: remove once the ssl cert verification is checked
    import ssl
    context = ssl._create_unverified_context()

    hawkular_alerts = HawkularAlertsGroupCondition(module, tenant, hostname, port, scheme, token, context)

    if state == "present":
        res_args = hawkular_alerts.create_group_condition(group_id, trigger_mode, type, data_id, operator, data)
    module.exit_json(**res_args)


# Import module bits
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
