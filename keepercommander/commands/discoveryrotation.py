#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Secrets Manager
# Copyright 2022 Keeper Security Inc.
# Contact: sm@keepersecurity.com
#
import argparse
import logging

from keeper_secrets_manager_core.configkeys import ConfigKeys

from keepercommander import utils, api
from keepercommander.commands.base import raise_parse_exception, suppress_exit
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.commands.utils import KSMCommand
from .base import GroupCommand, dump_report_data

from keepercommander.display import bcolors


dr_create_controller_parser = argparse.ArgumentParser(prog='dr-create-controller')
dr_create_controller_parser.add_argument('--name', '-n', required=True, dest='controller_name',  help='Name of the Controller', action='store')
dr_create_controller_parser.add_argument('--application', '-a', required=True, dest='ksm_app', help='KSM Application name or UID', action='store')
dr_create_controller_parser.add_argument('--return_value', '-r', dest='return_value', action='store_true', help='Return value from the command for automation purposes')
dr_create_controller_parser.add_argument('--config-init', '-c', type=str, dest='config_init', action='store', help='Initialize client config')    # json, b64, file

dr_create_controller_parser.error = raise_parse_exception
dr_create_controller_parser.exit = suppress_exit

dr_list_controllers_parser = argparse.ArgumentParser(prog='dr-list-controller')
dr_list_controllers_parser.error = raise_parse_exception
dr_list_controllers_parser.exit = suppress_exit


dr_client_connect_parser = argparse.ArgumentParser(prog='client-connect')
dr_client_connect_parser.error = raise_parse_exception
dr_client_connect_parser.exit = suppress_exit


def register_commands(commands):
    commands['dr'] = DRControllerCommand()


def register_command_info(_, command_info):
    command_info['dr'] = 'Manage Discovery and Rotation'


class DRControllerCommand(GroupCommand):

    def __init__(self):
        super(DRControllerCommand, self).__init__()
        self.register_command('controller-create', DRCreateControllerCommand(), 'Create discovery and rotation controller')
        self.register_command('controller-list', DRListControllersCommand(), 'View controllers')


class DRCreateControllerCommand(EnterpriseCommand):

    def get_parser(self):
        return dr_create_controller_parser

    def execute(self, params, **kwargs):

        controller_name = kwargs.get('controller_name')
        ksm_app = kwargs.get('ksm_app')
        is_return_value = kwargs.get('return_value')
        config_init = kwargs.get('config_init')

        new_client_name = controller_name + '-ctr'

        logging.debug(f'controller_name=[{controller_name}]')
        logging.debug(f'ksm_app        =[{ksm_app}]')

        one_time_tokens = KSMCommand.add_client(params,
                                                app_name_or_uid=ksm_app,
                                                count=1,
                                                unlock_ip=True,
                                                first_access_expire_on=5,     # if one time token not used in 5 min then it will be expired
                                                access_expire_in_min=None,    # how long the client has access to the application, None=Never, int = num of min
                                                client_name=new_client_name,
                                                config_init=False,
                                                silent=True)

        one_time_token = one_time_tokens[0]

        # get a hash of the one time token which is the same as Client ID in the config
        one_time_token_hash = KSMCommand.get_hash_of_one_time_token(one_time_token)

        if config_init:
            config_str_and_config_dict = KSMCommand.init_ksm_config(params, one_time_token, config_init,
                                                                    include_config_dict=True)

            one_time_token = config_str_and_config_dict.get('config_str')
            client_id = config_str_and_config_dict.get('config_dict').get(ConfigKeys.KEY_CLIENT_ID.value)
        else:
            client_id = one_time_token_hash

        rq = {
            'command': 'put_enterprise_setting',
            'type': 'RDControllerConfig',
            'settings': {
                'name': controller_name,
                'controllerUid': utils.generate_uid(),
                'clientId': client_id
            }
        }

        rs = api.communicate(params, rq)

        if is_return_value:
            return one_time_token
        else:
            print(f'Controller [{bcolors.OKBLUE}{controller_name}{bcolors.ENDC}] '
                  f'has be created and associated with client [{bcolors.OKBLUE}{new_client_name}{bcolors.ENDC}] '
                  f'in application [{bcolors.OKBLUE}{ksm_app}{bcolors.ENDC}]')

            if config_init:
                print('Use following initialized config be used in the controller:')
            else:
                print('Use following one time token to setup the controller:')

            print('--------------------------------')
            print(bcolors.OKGREEN + one_time_token + bcolors.ENDC)
            print('--------------------------------')


class DRListControllersCommand(EnterpriseCommand):

    def get_parser(self):
        return dr_list_controllers_parser

    def execute(self, params, **kwargs):

        rq = {
            'command': 'get_enterprise_setting',
            'include': ["RDControllerConfig"]
        }

        rs = api.communicate(params, rq)

        controllers = rs.get('RDControllerConfig')

        table = []
        headers = ['Uid', 'Name', 'Created', 'Modified', 'Client ID']
        for controller in controllers:
            row = [
                controller.get('controllerUid'),
                controller.get('name'),
                controller.get('created'),
                controller.get('modified'),
                controller.get('clientId')
            ]
            table.append(row)
        table.sort(key=lambda x: (x[3] or ''))

        dump_report_data(table, headers, fmt='table', filename="",
                         row_number=True, column_width=None)
