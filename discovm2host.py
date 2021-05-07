#! /usr/bin/env python
# # -*- coding: utf-8 -*-
""" Clone a "Dicover Vmware VMs" in Zabbix into a simple host to make it
editable"""

import argparse
import getpass
from pyzabbix import ZabbixAPI

__author__ = "Alain Devarieux"
__license__ = "GPL"
__version__ = 1.1
__maintainer__ = "Alain Devarieux"
__email__ = "alain@devarieux.net"


zabbixurl = "http://zabbix.url/folder"


def parseopt():
    parser = argparse.ArgumentParser(description="This script take a list of \
                                     hosts in argument and clone each host so \
                                     it can be writeable in Zabbix.\nNote:\
                                     Hostnames given in argument should be\
                                     'Visible Name' in Zabbix (or VM Name in\
                                     the vcenter)")
    parser.add_argument("--host",
                        nargs='+',
                        help="space separated list of hosts")
    parser.add_argument("-f",
                        "--file",
                        help="File containing a list of hosts (one by line)")
    parser.add_argument("-u",
                        "--username",
                        help="Zabbix user who connect to the Zabbix API",
                        required=True)
    args = parser.parse_args()
    if not (args.host or args.file):
        parser.error('No action requested use --host or --file')
    if args.host:
        return args.host, args.username
    if args.file:
        return open(args.file).read().splitlines(), args.username


def copyhost(hostname, username, userpass):
    '''
    Copy host 'hostname' as hostname-ApiCopy using Full Clone functionnality
    '''
    zapi = ZabbixAPI(zabbixurl)
    zapi.login(username,
               userpass)
    # print("Connected to Zabbix API Version %s" % zapi.api_version())
    # See Zabbix API Reference
    # https://www.zabbix.com/documentation/3.4/manual/api/reference
    prefix = "-ApiCopy"
    host = zapi.host.get(filter={"name": hostname},
                         selectGroups=['groupid'],
                         selectInterfaces=['ip',
                                           'useip',
                                           'dns',
                                           'bulk',
                                           'main',
                                           'type',
                                           'port'],
                         selectMacros=['macro',
                                       'value'],
                         selectParentTemplates=['templateid'])

    if host:
        host = host[0]
        host_name = host["name"]
        host_host = host["host"]
        print("Found host {0}".format(host_name))
        host_copy = host
        host_copy["name"] = host_name + prefix
        print host_copy["name"]
        host_copy["host"] = host_host + prefix
        print host_copy["host"]
        return zapi.host.create(host=host_copy['host'],
                                name=host_copy['name'],
                                proxy_hostid=host_copy['proxy_hostid'],
                                groups=host_copy['groups'],
                                interfaces=host_copy['interfaces'],
                                templates=host_copy['parentTemplates'])

    else:
        print("Host {0} not found".format(hostname))
        return "Not Found"


def deletehost(hostname, username, userpass):
    '''
    Delete host 'hostname'
    '''
    zapi = ZabbixAPI(zabbixurl)
    zapi.login(username,
               userpass)
    # print("Connected to Zabbix API Version %s" % zapi.api_version())
    # See Zabbix API Reference
    # https://www.zabbix.com/documentation/3.4/manual/api/reference
    host = zapi.host.get(filter={"name": hostname})
    if len(host) == 1:
        hostid = host[0]['hostid']
        print("Deleting host {0} {1} with id {2}".format(host[0]['host'],
                                                         host[0]['name'],
                                                         hostid))
        return zapi.host.delete(hostid)
    elif len(host) == 0:
        print("{0}: host not found".format(hostname))
        return "Not Found"
    else:
        print("There are several hosts corresponding to {0}:\n".format('hostname'))
        for elem in host:
            print("\tName {0} with id {1}\n".format(elem['name'],
                                                    elem['hostid']))
        return "Do Nothing"


def renamehost(hosthost, username, userpass):
    '''
    Rename host 'hosthost' to remove ApiCopy from its name
    '''
    zapi = ZabbixAPI(zabbixurl)
    zapi.login(username,
               userpass)
    # print("Connected to Zabbix API Version %s" % zapi.api_version())
    # See Zabbix API Reference
    # https://www.zabbix.com/documentation/3.4/manual/api/reference
    host = zapi.host.get(filter={"hostid": hosthost['hostids'][0]})
    if len(host) == 1:
        hostid = host[0]['hostid']
        host_name = host[0]['name']
        new_host_name = host_name[:-8]
        print new_host_name
        new_host_host = host[0]['host'][:-8]
        print new_host_host
        print("Renaming host {0} {1}".format(host[0]['host'],
                                             host[0]['name']))
        return zapi.host.update(hostid=hostid,
                                host=new_host_host,
                                name=new_host_name)
    elif len(host) == 0:
        print("{0}: host not found".format(hosthost))
        return "Not Found"
    else:
        print("There are several hosts corresponding to {0}:\n".format('hostname'))
        for elem in host:
            print("\tName {0} with id {1}\n".format(elem['name'],
                                                    elem['hostid']))
        return "Do Nothing"


def main():
    hostlist, username = parseopt()
    userpass = getpass.getpass('Password:')
    for host in hostlist:
        hostname_apicopy = copyhost(host, username, userpass)
        if hostname_apicopy == "Not Found":
            continue
        delhost = deletehost(host, username, userpass)
        if delhost == "Not Found" or delhost == "Do Nothing":
            continue
        renamehost(hostname_apicopy, username, userpass)


if __name__ == "__main__":
    main()
