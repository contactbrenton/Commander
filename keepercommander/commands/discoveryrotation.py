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
import json
import logging
import os
from datetime import datetime
from threading import Thread

from keeper_secrets_manager_core.configkeys import ConfigKeys

from keepercommander import utils, api
from keepercommander.commands.base import raise_parse_exception, suppress_exit
from keepercommander.commands.enterprise_common import EnterpriseCommand
from keepercommander.commands.utils import KSMCommand
from .base import GroupCommand, dump_report_data

from keepercommander.display import bcolors

WS_INIT = {'kind': 'init'}
WS_LOG_FOLDER = 'dr-logs'
WS_URL = 'wss://47ynnck3xd.execute-api.us-east-1.amazonaws.com/dev/'
WS_HEADERS = {
    'ClientVersion': 'ms16.2.4'
}


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


dr_connect_parser = argparse.ArgumentParser(prog='dr-connect')
dr_connect_parser.error = raise_parse_exception
dr_connect_parser.exit = suppress_exit

dr_disconnect_parser = argparse.ArgumentParser(prog='dr-disconnect')
dr_disconnect_parser.error = raise_parse_exception
dr_disconnect_parser.exit = suppress_exit

dr_cmd_parser = argparse.ArgumentParser(prog='dr-cmd')
dr_cmd_parser.add_argument(
    'command', nargs='*', type=str, action='store', help='Controller command'
)
dr_cmd_parser.error = raise_parse_exception
dr_cmd_parser.exit = suppress_exit



def register_commands(commands):
    commands['dr'] = DRControllerCommand()


def register_command_info(_, command_info):
    command_info['dr'] = 'Manage Discovery and Rotation'


class DRControllerCommand(GroupCommand):

    def __init__(self):
        super(DRControllerCommand, self).__init__()
        self.register_command('controller-create', DRCreateControllerCommand(), 'Create discovery and rotation controller')
        self.register_command('controller-list', DRListControllersCommand(), 'View controllers')
        self.register_command('connect', DRConnect(), 'Connect')
        self.register_command('disconnect', DRDisconnect(), 'Disconnect')
        self.register_command('cmd', DRCommand(), 'Send command')


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


class DRConnection:
    def __init__(self):
        if not os.path.isdir(WS_LOG_FOLDER):
            os.makedirs(WS_LOG_FOLDER)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.ws_log_file = os.path.join(WS_LOG_FOLDER, f'{timestamp}.log')
        self.ws_app = None
        self.thread = None

    def connect(self, session_token):
        try:
            import websocket
        except ImportError:
            logging.warning(f'websocket-client module is missing. '
                            f'Use following command to install it '
                            f'`{bcolors.OKGREEN}pip3 install -U websocket-client{bcolors.ENDC}`')
            return

        headers = WS_HEADERS
        headers['Auth'] = f'User {session_token}'
        self.ws_app = websocket.WebSocketApp(
            WS_URL, header=headers, on_open=self.on_open, on_message=self.on_message, on_error=self.on_error,
            on_close=self.on_close
        )
        self.thread = Thread(target=self.ws_app.run_forever)
        self.thread.start()

    def disconnect(self):
        if self.thread and self.thread.is_alive():
            self.ws_app.close()
            self.thread.join()

    def init(self):
        self.ws_app.send(json.dumps(WS_INIT))
        self.log('Connection initialized')

    def log(self, msg, time=True):
        with open(self.ws_log_file, 'a') as ws_log:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f ') if time else ''
            ws_log.write(f'{timestamp}{msg}\n')

    def send(self, command):
        message = {'kind': 'command', 'data': command}
        self.ws_app.send(json.dumps(message))
        self.log(f'Sent {command}')

    def process_event(self, event):
        if event['kind'] == 'ctl_state':
            new_controllers = event['controllers']
            # dropped = self.controllers - new_controllers
            self.log(f'New controllers: {new_controllers}')
        elif event['kind'] == 'ctl_cmd':
            command = event['command']
            self.log(f'Command: {command}')
        else:
            self.log(f'Event: {event}')

    def on_open(self, ws):
        self.log('Connection open')
        self.init()

    def on_message(self, ws, event_json):
        self.log(f'ws.listener.on_message:{event_json}')

        try:
            event = json.loads(event_json)
        except json.decoder.JSONDecodeError:
            self.log(f'Raw event: {event_json}')
        else:
            self.process_event(event)

    def on_error(self, ws, error_event):
        self.log(f'ws.listener.on_error:{error_event}')

    def on_close(self, ws, close_status_code, close_msg):
        self.log(f'ws.listener.on_close: close_status_code=[{close_status_code}], close_msg=[{close_msg}]')


class DRConnect(EnterpriseCommand):
    def get_parser(self):
        return dr_connect_parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            params.ws = DRConnection()
            params.ws.connect(params.session_token)
            logging.info(f'Connected {params.config["device_token"]}')
        else:
            logging.warning('Connection exists')


class DRDisconnect(EnterpriseCommand):
    def get_parser(self):
        return dr_disconnect_parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            logging.warning("Connection doesn't exist")
        else:
            params.ws.disconnect()
            params.ws = None


class DRCommand(EnterpriseCommand):
    def get_parser(self):
        return dr_cmd_parser

    def execute(self, params, **kwargs):
        if getattr(params, 'ws', None) is None:
            logging.warning("Connection doesn't exist")
        else:
            command = kwargs.get('command', [])
            params.ws.send(json.dumps(command))
