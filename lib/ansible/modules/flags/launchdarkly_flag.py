#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Ansible Project
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'community',
}

DOCUMENTATION = r'''
---
module: launchdarkly_flag
short_description: Interact with projects, flags of LaunchDarkly
description:
     - Manage LaunchDarkly manage feature flags and account settings.
version_added: "2.9"
options:
    state:
        description:
            - Indicate desired state of the resource
        choices: [ absent, enabled, disabled, deleted, present ]
        default: present
    api_key:
        description:
            - LaunchDarkly API Key
    name:
        description:
            - Name of the flag, if not provided and API calls requires it, key value will be used.
    type:
        description:
            - Set what type of flag this will be.
        choices: [ bool, str, number, json ]
        default: bool
    temporary:
        description:
            - Toggle if flag is temporary or permanent
        type: bool
        default: 'yes'
    project_key:
        description:
            - Project key will group flags together
        default: 'default'
    key:
        description:
            - A unique key that will be used to reference the flag in your code.
        required: yes
        type: str
'''

EXAMPLES = r'''
# Create a new flag
- launchdarkly_flag:
    name: "example"
    type: bool
    state: present
    temporary: false
    key: "example_faw43tq"
    targets: { environment: 'production', on: True}
'''

import inspect
import traceback

LD_IMP_ERR = None
try:
    import launchdarkly_api
    from launchdarkly_api.rest import ApiException

    HAS_LD = True
except ImportError:
    LD_IMP_ERR = traceback.format_exc()
    HAS_LD = False

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils._text import to_native
from ansible.module_utils.common._json_compat import json
from ansible.module_utils.six import PY2, iteritems, string_types


def main():
    mutually_exclusive=[
    ['clone', 'include_in_snippet'],['clone', 'state'],['clone','tags']

    ]

    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present',
                       choices=['absent', 'present', 'enabled', 'disabled']),
            api_key=dict(type='str', no_log=True),
            name=dict(type='str'),
            type=dict(choises=['str', 'bool', 'json', 'number'],required_if=["state", "present"]),
            project_key=dict(default='default',type='str'),
            key=dict(required=True,type='str'),
            temporary=dict(type='bool',default=True),
            tags=dict(type='list'),
            description=dict(type='str'),
            variations=dict(type='raw'),
            targets=dict(type='dict'),
            config=dict(type='jsonarg'),
            include_in_snippet=dict(type='bool',default=False),
            flag_enabled=dict(type='bool', default=False),
            comments=dict(type='str'),
            clone=dict(type='jsonarg'),
        ),
        mutually_exclusive=mutually_exclusive,
    )

    if not HAS_LD:
        module.fail_json(msg=missing_required_lib('launchdarkly_api'), exception=LD_IMP_ERR)

    # Some calls require feature_flag_key instead of key, so map that value to both keys
    kwargs = dict(project_key=module.params['project_key'], key=module.params['key'],
                  feature_flag_key=module.params['key'], tags=module.params['tags'],
                  description=module.params['description'],variations=module.params['variations'],
                  temporary=module.params['temporary'],include_in_snippet=module.params['include_in_snippet'])

    if module.params['name'] is not None:
        kwargs['name'] = module.params['name']
    else:
        kwargs['name'] = kwargs['key']

    # Not in active use, considering using options related to temporary, include_in_snippet, track_events and others.
    # Exploring same use as this example to then be parsed: https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/network/avi/avi_api_session.py
    config = module.params.get('config', None)
    if config is not None:
        config = json.loads(config)
    #_parse_config(config)

    # Operation dict was getting looked at for workflows related to patching calls.
    operations = dict(on=module.params['flag_enabled'])

    #Set up API
    configuration = launchdarkly_api.Configuration()
    configuration.api_key['Authorization'] = module.params['api_key']
    api_instance = launchdarkly_api.FeatureFlagsApi(launchdarkly_api.ApiClient(configuration))
    # Not used now, for enabling flag it happens for all environments in loop below.
    environments = { 'production': module.params['config'] }

    kwargs['environments'] = environments
    if module.params['state'] == 'present':
        _add_flag(module, configuration, api_instance, operations, **kwargs)
    elif module.params['state'] == 'absent':
        _delete_flag(module, configuration, api_instance, **kwargs)
    #Not enabled yet.
    elif module.params['state'] == 'enabled' or module.params['state'] == 'disabled':
        toggle_flag(module, configuration, api_instance, operations)


def _add_flag(module, configuration, api_instance, operations, **kwargs):
    ffb_kwargs = _clean_api_calls(launchdarkly_api.FeatureFlagBody, **kwargs)
    pff_kwargs = _clean_api_calls(launchdarkly_api.FeatureFlagsApi.patch_feature_flag, **kwargs)

    if module.params['type'] == 'bool':
        ffb_kwargs['variations'] = [launchdarkly_api.Variation(value=True), launchdarkly_api.Variation(value=False)]
    elif module.params['type'] == 'json':
        # No easy way to check isinstance json
        ffb_kwargs['variations'] = _build_variations(**ffb_kwargs)
    elif module.params['type'] == 'str':
        if not all(isinstance(item, str) for item in module.params['variations']):
            module.exit_json(msg="Variations need to all be strings")
        ffb_kwargs['variations'] = _build_variations(**ffb_kwargs)
    elif module.params['type'] == 'number':
        if not all(isinstance(item, int) for item in module.params['variations']):
            module.exit_json(msg="Variations need to all be integers")
        ffb_kwargs['variations'] = _build_variations(**ffb_kwargs)

    feature_flag_body = launchdarkly_api.FeatureFlagBody(**ffb_kwargs)

    try:
        if module.params['clone']:
            api_response = api_instance.post_feature_flag(module.params['project_key'], feature_flag_body, clone=module.params['clone'])
        else:
            api_response = api_instance.post_feature_flag(module.params['project_key'], feature_flag_body)

        env_list = []
        for environment,value in iteritems(api_response.environments):
            env_list.append(environment)

        if operations['on']:
            patches = []
            for environment in env_list:
                env_path = "/environments/" + environment + '/on'
                patch = launchdarkly_api.PatchOperation(op='replace',path=env_path,value=True)
                patches.append(patch)

            if module.params['comments'] is None:
                comment = "Ansible generated operation."
                comments = dict(comment=comment, patch=patches)
                api_response = api_instance.patch_feature_flag(module.params['project_key'],pff_kwargs['feature_flag_key'], patch_comment=patches)

        module.exit_json(msg=api_response)
    except ApiException as e:
        err = json.loads(str(e.body))
        if err['code'] == 'key_exists':
            module.exit_json(msg='error: Key already exists')
        else:
            module.exit_json(msg=err)


def _delete_flag(module, configuration, api_instance, **kwargs):
    kwargs = _clean_api_calls(api_instance.delete_feature_flag, **kwargs)
    try:
        api_response = api_instance.delete_feature_flag(**kwargs)
        module.exit_json(msg="")
    except ApiException as e:
        err = json.loads(str(e.body))
        module.exit_json(msg=err)


def toggle_flag(module):
    #placeholder
    print(module)


# Inspect the function signature to only pass in the required parameters.
def _clean_api_calls(api_call, **kwargs):
    api_args = inspect.getargspec(api_call).args
    for key in list(kwargs):
        if key not in api_args:
            kwargs.pop(key, None)
    return kwargs


def _build_variations(**kwargs):
    variation_list = []
    for item in kwargs['variations']:
        variation_list.append(launchdarkly_api.Variation(value=item))
    return variation_list


def _parse_config(config):
    print(config)
    #
    if config['on'] or module.params['flag_enabled']:
        config['on'] = True
    else:
        config['on'] = False

if __name__ == '__main__':
    main()