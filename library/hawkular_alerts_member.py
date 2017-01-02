#!/usr/bin/python


DOCUMENTATION = '''
---
module: hawkular_alerts_member
short_description: Creating Group Trigger Members in Hawkular Alerting
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
      - the group trigger id
    required: True
  id:
    description:
      - the group member id
    default: null
    required: False
  data_id_map:
    description:
      - a mapping of the token to the real data_id
    required: True
  name:
    description:
      - the group member name
    default: null
    required: False
  state:
    description:
      - the state of the user
      - On present, it will create the group trigger
      if it does not exist
    required: True
    choices: ['present', 'absent']
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
'''

EXAMPLES = '''
# create group member
  hawkular_alerts_member:
    hawkular_api_hostname: 'hawkular-endpoint.example.com'
    port: 443
    token: '******'
    tenant: '_system'
    state: 'present'
    group_id: 'example-group-trigger'
    id: 'member1'
    name: 'Member One'
    data_id_map:
      my-metric-id: my-metric-id-member1
'''

import urllib2
import hawkular.alerts

# TODO: remove once the ssl cert verification is checked
import os


class HawkularAlertsGroupMember(object):
    """ Hawkular Alerts object to create group members in Hawkular
    """
    def __init__(self, module, tenant, hostname, port, scheme, token, context):
        self.module  = module
        self.client  = hawkular.alerts.HawkularAlertsClient(tenant, host=hostname, port=port, scheme=scheme, token=token, context=context)
        self.changed = False

    def group_trigger_exist(self, group_id):
        """
            Returns:
                True if a group trigger with the passed id exist, False otherwise
        """
        try:
            self.client.get_trigger(group_id)
            return True
        except urllib2.HTTPError as err:
            if err.code == 404:
                return False
            else:
                self.module.fail_json(msg="Failed to get group trigger. Error: {error}".format(error=err))

    def create_group_member(self, group_id, member_id, data_id_map, member_name=None):
        """ Creates a group member in Hawkular Alerting component

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        if not self.group_trigger_exist(group_id):
            self.module.fail_json(msg="Failed to create group member, group {group_id} does not exist ".format(group_id=group_id))
        try:
            #  create group member object
            member = hawkular.alerts.GroupMemberInfo()
            member.group_id = group_id
            member.member_id = member_id
            member.member_name = member_name
            member.data_id_map = data_id_map
            self.client.create_group_member(member)
            self.changed = True
            return dict(
                msg="Successfully created group member {member_id}".format(member_id=member_id),
                changed=self.changed)
        except Exception as e:
            self.module.fail_json(msg="Failed to create group member. Error: {error}".format(error=e))


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
            state=dict(required=True, type='str', choices=['present', 'absent']),
            group_id=dict(required=True, type='str'),
            id=dict(required=True, type='str'),
            name=dict(required=False, type='str'),
            data_id_map=dict(required=True, type='dict'),
            scheme=dict(required=False, type='str', choices=['https', 'http'], default='https'),
        ),
    )

    for arg in ['hawkular_api_hostname', 'hawkular_api_port', 'hawkular_api_auth_token']:
        if module.params[arg] in (None, ''):
            module.fail_json(msg="missing required argument: {}".format(arg))

    hostname    = module.params['hawkular_api_hostname']
    port        = module.params['hawkular_api_port']
    token       = module.params['hawkular_api_auth_token']
    tenant      = module.params['tenant']
    group_id    = module.params['group_id']
    member_id   = module.params['id']
    member_name = module.params['name']
    data_id_map = module.params['data_id_map']
    scheme      = module.params['scheme']
    state       = module.params['state']

    # TODO: remove once the ssl cert verification is checked
    import ssl
    context = ssl._create_unverified_context()

    hawkular_alerts = HawkularAlertsGroupMember(module, tenant, hostname, port, scheme, token, context)

    if state == "present":
        res_args = hawkular_alerts.create_group_member(group_id, member_id, data_id_map, member_name)
    module.exit_json(**res_args)


# Import module bits
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
