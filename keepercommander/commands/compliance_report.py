#  _  __
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|
#
# Keeper Commander
# Copyright 2022 Keeper Security Inc.
# Contact: ops@keepersecurity.com
#

import argparse
import datetime

from .base import dump_report_data, Command, GroupCommand
from .. import utils, api
from ..proto import enterprise_pb2

compliance_report_list_parser = argparse.ArgumentParser(prog='compliance-report list')

compliance_report_view_parser = argparse.ArgumentParser(prog='compliance-report view')
compliance_report_view_parser.add_argument('target', help='Compliance report UID or Name.')
compliance_report_view_parser.add_argument('--format', dest='format', action='store', choices=['screen', 'json'],
                                           default='screen', help='output format.')
compliance_report_view_parser.add_argument('--output', dest='output', action='store',
                                           help='output file name. (ignored for table format)')


class ComplianceReportCommand(GroupCommand):
    def __init__(self):
        super(ComplianceReportCommand, self).__init__()
        self.register_command('list', ComplianceReportListCommand(), 'Prints a list of compliance reports')
        self.register_command('view', ComplianceReportViewCommand(), 'Prints detail information about compliance report')
        # self.register_command('keep', ShortcutKeepCommand(), 'Removes shortcuts except one')
        self.default_verb = 'list'

    @staticmethod
    def find_compliance_report_uid(params, target):
        if not target:
            raise Exception('Compliance report name cannot be empty')
        if isinstance(target, str):
            if 'compliance_reports' in params.enterprise:
                for report in params.enterprise['compliance_reports']:
                    if report['report_uid'] == target:
                        return report['report_uid']
                    if report['report_name'].casefold() == target.casefold():
                        return report['report_uid']
        raise Exception(f'Compliance report {target} not found')


class ComplianceReportListCommand(Command):
    def get_parser(self):
        return compliance_report_list_parser

    def execute(self, params, **kwargs):
        table = []
        headers = ['Report UID', 'Report Name', 'Generated']
        if 'compliance_reports' in params.enterprise:
            for report in params.enterprise['compliance_reports']:
                generated_at = report.get('date_generated', 0)
                if generated_at:
                    dt = datetime.datetime.fromtimestamp(generated_at / 1000)
                    generated_at = str(dt)
                else:
                    generated_at = ''
                table.append([report['report_uid'], report['report_name'], generated_at])
        dump_report_data(table, headers=headers)


class ComplianceReportViewCommand(Command):
    def get_parser(self):
        return compliance_report_view_parser

    def execute(self, params, **kwargs):
        report_uid = ComplianceReportCommand.find_compliance_report_uid(params, kwargs.get('target'))

        rq = enterprise_pb2.GetComplianceReportRequest()
        rq.reportUid = utils.base64_url_decode(report_uid)
        rs = api.communicate_rest(params, rq, 'enterprise/get_compliance_report',
                                  rs_type=enterprise_pb2.ComplianceReportResponse)
        if rs:
            pass

