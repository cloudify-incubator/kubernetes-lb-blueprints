#!/usr/bin/env python
#
# Copyright (c) 2017 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import platform
import socket
import ssl
import subprocess
import tempfile
import os.path

from cloudify import ctx
from cloudify.state import ctx_parameters as inputs
from cloudify.exceptions import (
    HttpException,
    NonRecoverableError,
    OperationRetry
)


def download_service(service_name):
    service_path = "/usr/bin/" + service_name
    if not os.path.isfile(service_path):
        try:
            cfy_binary = ctx.download_resource(
                'resources/{}'.format(service_name))
        except HttpException:
            raise NonRecoverableError(
                '{} binary not in resources.'.format(service_name))
        ctx.logger.debug('{} downloaded.'.format(service_name))
        if execute_command(['sudo', 'cp', cfy_binary, service_path]) is False:
            raise NonRecoverableError("Can't copy {}.".format(service_path))
    # fix file attributes
    if execute_command(['sudo', 'chmod', '555', service_path]) is False:
        raise NonRecoverableError("Can't chmod {}.".format(service_path))
    if execute_command(['sudo', 'chown', 'root:root', service_path]) is False:
        raise NonRecoverableError("Can't chown {}.".format(service_path))
    ctx.logger.debug('{} attributes fixed'.format(service_name))


def execute_command(command, extra_args=None):

    ctx.logger.debug('command: {0}.'.format(repr(command)))

    subprocess_args = {
        'args': command,
        'stdout': subprocess.PIPE,
        'stderr': subprocess.PIPE
    }
    if extra_args is not None and isinstance(extra_args, dict):
        subprocess_args.update(extra_args)

    ctx.logger.debug('subprocess_args {0}.'.format(subprocess_args))

    process = subprocess.Popen(**subprocess_args)
    output, error = process.communicate()

    ctx.logger.debug('command: {0} '.format(repr(command)))
    ctx.logger.debug('output: {0} '.format(output))
    ctx.logger.debug('error: {0} '.format(error))
    ctx.logger.debug('process.returncode: {0} '.format(process.returncode))

    if process.returncode:
        ctx.logger.error('Running `{0}` returns {1} error: {2}.'
                         .format(repr(command), process.returncode,
                                 repr(error)))
        return False

    return output

def start_check(service_name):
    status_string = ''
    systemctl_status = execute_command(['sudo', 'systemctl', 'status',
                                        '{}.service'.format(service_name)])
    if not isinstance(systemctl_status, basestring):
        raise OperationRetry(
            'check sudo systemctl status {}.service'.format(service_name))
    for line in systemctl_status.split('\n'):
        if 'Active:' in line:
            status = line.strip()
            zstatus = status.split(' ')
            ctx.logger.debug('{} status line: {}'
                             .format(service_name, repr(zstatus)))
            if len(zstatus) > 1:
                status_string = zstatus[1]

    ctx.logger.info('{} status: {}'.format(service_name, repr(status_string)))
    if 'active' != status_string:
        raise OperationRetry('Wait a little more.')
    else:
        ctx.logger.info('Service {} is started.'.format(service_name))


def get_instance_host(relationships, rel_type, target_type):
    for rel in relationships:
        if rel.type == rel_type or rel_type in rel.type_hierarchy:
            if target_type in rel.target.node.type_hierarchy:
                return rel.target.instance
            instance = get_instance_host(rel.target.instance.relationships,
                                         rel_type, target_type)
            if instance:
                return instance
    return None


def update_host_address(host_instance, hostname, fqdn, ip, public_ip):
    ctx.logger.info('Setting initial Kubernetes node data')

    if not public_ip:
        public_ip_prop = host_instance.runtime_properties.get(
            'public_ip')
        public_ip_address_prop = host_instance.runtime_properties.get(
            'public_ip_address')
        public_ip = public_ip_prop or public_ip_address_prop or ip

    new_runtime_properties = {
        'name': ctx.instance.id,
        'hostname': hostname,
        'fqdn': fqdn,
        'ip': ip,
        'public_ip': public_ip
    }

    for key, value in new_runtime_properties.items():
        ctx.instance.runtime_properties[key] = value

    ctx.logger.info(
        'Finished setting initial Kubernetes node data.')


if __name__ == '__main__':

    host_instance = get_instance_host(ctx.instance.relationships,
                                      'cloudify.relationships.contained_in',
                                      'cloudify.nodes.Compute')
    if not host_instance:
        raise NonRecoverableError('Ambiguous host resolution data.')

    cloudify_agent = host_instance.runtime_properties.get('cloudify_agent', {})
    linux_distro = cloudify_agent.get('distro')
    cfy_host = cloudify_agent.get('broker_ip')
    cfy_ssl_port = cloudify_agent.get('rest_port')

    if ctx.operation.retry_number == 0:
        # Allow user to provide specific values.
        update_host_address(
            host_instance=host_instance,
            hostname=inputs.get('hostname', socket.gethostname()),
            fqdn=inputs.get('fqdn', socket.getfqdn()),
            ip=inputs.get('ip', ctx.instance.host_ip),
            public_ip=inputs.get('public_ip'))

        # certificate logic
        if not linux_distro:
            distro, _, _ = \
                platform.linux_distribution(full_distribution_name=False)
            linux_distro = distro.lower()

        ctx.logger.info("Set certificate as trusted")

        # cert config
        _, temp_cert_file = tempfile.mkstemp()

        with open(temp_cert_file, 'w') as cert_file:
            cert_file.write("# cloudify certificate\n")
            try:
                cert_file.write(ssl.get_server_certificate((
                    cfy_host, cfy_ssl_port)))
            except Exception as ex:
                ctx.logger.error("Check https connection to manager {}."
                                 .format(str(ex)))

        if 'centos' in linux_distro:
            execute_command([
                'sudo', 'cp', temp_cert_file,
                '/etc/pki/ca-trust/source/anchors/cloudify.crt'
            ])
            execute_command([
                'sudo', 'update-ca-trust', 'extract'
            ])
            execute_command([
                'sudo', 'bash', '-c',
                'cat {} >> /etc/pki/tls/certs/ca-bundle.crt'
                .format(temp_cert_file)
            ])
        else:
            raise NonRecoverableError('Unsupported platform.')