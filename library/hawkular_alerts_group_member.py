#!/usr/bin/python


DOCUMENTATION = '''
---
module: hawkular_alerts_group_member
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
  tags:
    description:
      - Tags defined by the user for this trigger. A tag is a [name, value] pair
    default: null
    required: False
  name:
    description:
      - the group member name
    default: null
    required: False
  description:
    description:
      - the group member description
    default: null
    required: False
  state:
    description:
      - the state of the user
      - On present, it will create the group member trigger
      if it does not exist
      - On absent, it will delete the group member trigger
      if it exists
      - On list, it will find all group member triggers
    required: True
    choices: ['present', 'absent', 'list']
  scheme:
    description:
      - the hawkular scheme
    default: 'https'
    required: False
    choices: ['https', 'http']
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
    description: 'this is a member of example-group-trigger'
    data_id_map:
      my-metric-id: my-metric-id-member1
    tags:
      nodename: mynode.example.com
    verify_ssl: True
    ca_file_path: /path/to/cafile.pem
'''

import os
import ssl
import urllib2
import hawkular.alerts


class HawkularAlertsGroupMember(object):
    """ Hawkular Alerts object to create group members in Hawkular
    """
    def __init__(self, module, tenant, hostname, port, scheme, token, context):
        self.module  = module
        self.client  = hawkular.alerts.HawkularAlertsClient(tenant, host=hostname, port=port, scheme=scheme, token=token, context=context)
        self.changed = False

    def list_group_members(self, group_id):
        """  Returns:
                 all group member triggers
        """
        if not self.group_trigger_exist(group_id):
            self.module.fail_json(msg="Failed to list group members of group {group_id}".format(group_id=group_id))
        try:
            group_members = self.client.get_group_members(group_id)
            group_members_dicts_list = [vars(member) for member in group_members]
        except Exception as e:
            self.module.fail_json(msg="Failed to get group member triggers. Error: {error}".format(error=e))
        return dict(
            msg="Successfuly listed group {group_id} member triggers".format(group_id=group_id),
            changed=self.changed,
            group_members=group_members_dicts_list)

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

    def group_member_exist(self, group_id, id):
        """
        Searches the member ID in the group trigger's members

        Returns:
            True if the member already exist, False otherwise
        """
        try:
            group_members = self.client.get_group_members(group_id)
        except Exception as e:
            self.module.fail_json(msg="Failed to get group members. Error: {error}".format(error=e))
        return any(gm.id == id for gm in group_members)

    def delete_group_member(self, group_id, id):
        """ Deletes an existing group member trigger
        """
        if not self.group_member_exist(group_id, id):
            return dict(
                msg="Group member {id} does not exist, nothing to do".format(
                    id=id),
                changed=self.changed)
        try:
            self.client.delete_trigger(id)
        except Exception as e:
            self.module.fail_json(msg="Failed to delete group member {id}. Error: {error}".format(
                id=id, error=e))
        self.changed = True
        return dict(
            msg="Successfully deleted group member {id}".format(id=id),
            changed=self.changed)

    def create_group_member(self, group_id, id, data_id_map, tags=None, name=None, description=None):
        """ Creates a group member in Hawkular Alerting component

            Returns:
                whether or not a change took place and a short message
                describing the operation executed
        """
        if not self.group_trigger_exist(group_id):
            self.module.fail_json(msg="Failed to create group member, group {group_id} does not exist ".format(group_id=group_id))
        if self.group_member_exist(group_id, id):
            return dict(
                msg="Group member {name} already exist in group {group_id}".format(
                    name=name, group_id=group_id),
                changed=self.changed)
        try:
            #  create group member object
            member = hawkular.alerts.GroupMemberInfo()
            member.group_id = group_id
            member.member_id = id
            member.member_name = name
            member.member_description = description
            member.data_id_map = data_id_map
            member.member_tags = tags
            self.client.create_group_member(member)
            self.changed = True
            return dict(
                msg="Successfully created group member {id}".format(id=id),
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
                default=os.environ.get('HAWKULAR_TOKEN'), type='str', no_log=True),
            tenant=dict(required=True, type='str'),
            state=dict(required=True, type='str', choices=['present', 'absent', 'list']),
            group_id=dict(required=True, type='str'),
            id=dict(required=False, type='str'),
            name=dict(required=False, type='str'),
            description=dict(required=False, type='str'),
            data_id_map=dict(required=False, type='dict'),
            tags=dict(required=False, type='dict'),
            scheme=dict(required=False, type='str', choices=['https', 'http'], default='https'),
            ca_file_path=dict(required=False, type='str'),
            verify_ssl=dict(required=False, type='bool', default=True),
        ),
        required_if=[('state', 'present', ['id', 'data_id_map'])],
    )

    for arg in ['hawkular_api_hostname', 'hawkular_api_port', 'hawkular_api_auth_token']:
        if module.params[arg] in (None, ''):
            module.fail_json(msg="missing required argument: {}".format(arg))

    hostname    = module.params['hawkular_api_hostname']
    port        = module.params['hawkular_api_port']
    token       = module.params['hawkular_api_auth_token']
    tenant      = module.params['tenant']
    group_id    = module.params['group_id']
    id          = module.params['id']
    name        = module.params['name']
    description = module.params['description']
    data_id_map = module.params['data_id_map']
    tags        = module.params['tags']
    scheme      = module.params['scheme']
    state       = module.params['state']
    verify_ssl  = module.params['verify_ssl']
    ca_file     = module.params['ca_file_path']

    context = None
    if not verify_ssl:
        context = ssl._create_unverified_context()
    elif ca_file:
        context = ssl.create_default_context(cafile=ca_file)

    hawkular_alerts = HawkularAlertsGroupMember(module, tenant, hostname, port, scheme, token, context)

    if state == "present":
        res_args = hawkular_alerts.create_group_member(group_id, id, data_id_map, tags, name, description)
    elif state == "absent":
        res_args = hawkular_alerts.delete_group_member(group_id, id)
    elif state == "list":
        res_args = hawkular_alerts.list_group_members(group_id)
    module.exit_json(**res_args)


# Import module bits
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
