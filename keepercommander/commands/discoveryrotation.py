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

from keepercommander import utils, api
from keepercommander.commands.base import raise_parse_exception, suppress_exit
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.commands.utils import KSMCommand
from .base import GroupCommand, dump_report_data

from keepercommander.display import bcolors


dr_create_controller_parser = argparse.ArgumentParser(prog='dr-create-controller')
dr_create_controller_parser.add_argument('--name', '-n', required=True, dest='controller_name',  help='Name of the Controller', action='store')
dr_create_controller_parser.add_argument('--application', '-a', required=True, dest='ksm_app', help='KSM Application name or UID', action='store')
dr_create_controller_parser.error = raise_parse_exception
dr_create_controller_parser.exit = suppress_exit

dr_list_controllers_parser = argparse.ArgumentParser(prog='dr-list-controller')
dr_list_controllers_parser.error = raise_parse_exception
dr_list_controllers_parser.exit = suppress_exit


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


        # Convert/Initialize token to full config

        config_dict = KSMCommand.init_ksm_config(params, one_time_token=one_time_tokens[0], config_init='dict')

        client_id = config_dict.get('clientId')
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

        logging.debug(str(rs))
        print(f'Controller [{bcolors.OKBLUE}{controller_name}{bcolors.ENDC}] '
              f'has be created and associated with client [{bcolors.OKBLUE}{new_client_name}{bcolors.ENDC}] '
              f'in application [{bcolors.OKBLUE}{ksm_app}{bcolors.ENDC}]')

        config_json = KSMCommand.convert_config_dict(config_dict, conversion_type='json')

        print('--------------------------------')
        print('Use following config in the client and controller:')

        print(bcolors.OKGREEN + config_json + bcolors.ENDC)


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
