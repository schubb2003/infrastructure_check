#!/usr/bin/python3
"""
# Author: Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have been
#   tested in lab situations, all use cases cannot be accounted for.
# 4 Sept 2019, updated to add gethostbyaddr for lookup and ping
"""

import json
import os
import socket
import datetime
import requests
from platform import system as system_name
from prettytable import PrettyTable
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from choose_inputs import get_inputs_default as get_inputs
from build_auth import build_auth
from connect_cluster import connect_cluster_rest as connect_cluster
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def build_payload(call):
    """
    Used to build the payloads we will run against the cluster
    """
    payload = json.dumps({"method": call, "params": {"force": True}, "id": 1})
    return payload


def get_outputs(headers, url):
    """
    Loop through  the calls required and output them all into a dictionary.
    The call is the key and the output is the value for the dictionary
    """
    output_dict = {}
    api_calls = "GetClusterCapacity", "GetClusterInfo", "ListClusterPairs", \
                "ListActivePairedVolumes", "GetSnmpTrapInfo", "GetNtpInfo", \
                "ListDrives", "ListActiveNodes", "ListPendingNodes", \
                "ListPendingActiveNodes", "GetClusterVersionInfo", \
                "GetNetworkConfig", "ListVirtualNetworks", \
                "GetClusterHardwareInfo", "GetHardwareInfo", \
                "GetClusterSshInfo", "GetLdapConfiguration", \
                "ListClusterAdmins"
    for call in api_calls:
        print("Gathering information from: {}".format(call))
        payload = build_payload(call)
        response_json = connect_cluster(headers, url, payload)
        output_dict[call] = response_json
    return output_dict

def get_cluster_capacity(**output_dict):
    """
    Gets the base capacity
    """
    out_dict = {}
    response_json = output_dict['GetClusterCapacity']
    max_usable = response_json['result']['clusterCapacity']['maxUsedSpace']
    gb_usable_no_prot = (max_usable/1000/1000/1000)
    gib_usable_no_prot = (max_usable/1024/1024/1024)
    #SolidFire GUI uses base10 math, does not include protection space
    #  Output both base10 and base2 as well as usable and protected usable

    max_usable_gb_no_helix = 'Max usable GB without double helix'
    max_usable_gb_helix = 'Max usable GB with double helix'
    max_usable_gib_no_helix = 'Max usable GiB without double helix'
    max_usable_gb_helix = 'Max usable GiB with double helix'

    out_dict[max_usable_gb_no_helix] = round(gb_usable_no_prot, 2)
    out_dict[max_usable_gb_helix] = round((gb_usable_no_prot/2), 2)
    out_dict[max_usable_gib_no_helix] = round(gib_usable_no_prot, 2)
    out_dict[max_usable_gb_helix] = round((gib_usable_no_prot/2), 2)
    hdr1 = 'Capacity type'
    hdr2 = 'Output'
    return hdr1, hdr2, out_dict


def get_cluster_info(**output_dict):
    """
    Gets the cluster name, mvip ip, svip ip, unique ID,
        encryption state, and default VLAN IDs
    """
    response_json = output_dict['GetClusterInfo']
    out_dict = {}
    result_cls_info = response_json['result']['clusterInfo']
    cls_name = result_cls_info['name']
    cls_mvip = result_cls_info['mvip']
    cls_mvip_vlan = result_cls_info['mvipVlanTag']
    cls_unique_id = result_cls_info['uniqueID']
    cls_encrypt = result_cls_info['encryptionAtRestState']
    cls_svip = result_cls_info['svip']
    cls_svip_vlan = result_cls_info['svipVlanTag']
    out_dict['Cluster Name'] = cls_name
    out_dict['Cluster MVIP'] = cls_mvip
    out_dict['Cluster MVIP VLAN'] = cls_mvip_vlan
    out_dict['Cluster Unique ID'] = cls_unique_id
    out_dict['Encryption State'] = cls_encrypt
    out_dict['Cluster SVIP'] = cls_svip
    out_dict['Cluster SVIP VLAN'] = cls_svip_vlan
    hdr1 = 'Cluster Configuration'
    hdr2 = 'Setting'
    return hdr1, hdr2, out_dict


def get_cluster_version(**output_dict):
    """
    Get the cluster version as we don't keep that in cluster info
    """
    out_dict = {}
    response_json = output_dict['GetClusterVersionInfo']
    # print(json.dumps(response_json, sort_keys=True, indent=4))
    hdr1 = 'Setting'
    hdr2 = 'Output'
    out_dict['Cluster Version'] = response_json['result']['clusterVersion']
    return hdr1, hdr2, out_dict


def get_cluster_pairs(**output_dict):
    """
    Check if the cluster is paired and provide the partner if it is
    Returns the name, unique id, mvip, connected/disconnected
        status and version of the remote partner
    """
    out_dict = {}
    response_json = output_dict['ListClusterPairs']
    for cluster in response_json['result']['clusterPairs']:
        remote_cls = cluster['clusterName']
        remote_uuid = cluster['clusterUUID']
        remote_mvip = cluster['mvip']
        remote_status = cluster['status']
        remote_version = cluster['version']
        out_dict['Remote cluster name'] = remote_cls
        out_dict['Remote cluster Unique ID'] = remote_uuid
        out_dict['Remote cluster MVIP'] = remote_mvip
        out_dict['Remote cluster status'] = remote_status
        out_dict['Remote cluster version'] = remote_version
    hdr1 = 'Pairing Information'
    hdr2 = 'Output'
    if len(out_dict) == 0:
        out_dict['Pairing status'] = "Not paired"
        remote_cls = None
    return hdr1, hdr2, out_dict


def get_hardware_info(**output_dict):
    """
    Get the serial number/service tag of the node
    Does not directly output anything on its own,
        used in merge_dictionary function
    """
    hw_dict = {}
    response_json = output_dict['GetHardwareInfo']
    # print(json.dumps(response_json, sort_keys=True, indent=4))
    for node in response_json['result']['nodes']:
        node_id = node['nodeID']
        node_serial = node['result']['hardwareInfo']['chassisSerial']
        hw_dict[node_id] = node_serial
    return hw_dict


def get_active_nodes(**output_dict):
    """
    Get the information on the active nodes, including all IPs,
        EOS version, mode and node name
    """
    out_dict = {}
    node_dict = {}
    virt_net_dict = {}
    node_count = 0
    response_json = output_dict['ListActiveNodes']
    virt_net_json = output_dict['ListVirtualNetworks']
    for net in virt_net_json['result']['virtualNetworks']:
        vlan_tag = net['virtualNetworkTag']
        vlan_id = net['virtualNetworkID']
        virt_net_dict[vlan_id] = vlan_tag
    for node in response_json['result']['nodes']:
        node_id = str(node['nodeID'])
        out_dict['------Node ID ' + node_id + ' ------'] = \
            '--------------------------'
        out_dict['Node ID ' + node_id + ' name'] = (node['name'])
        out_dict['Node ID ' + node_id + ' management IP'] = (node['mip'])
        out_dict['Node ID ' + node_id + ' storage IP'] = (node['sip'])
        out_dict['Node ID ' + node_id + ' version'] = (node['softwareVersion'])
        out_dict['Node ID ' + node_id + ' model'] = (node['platformInfo']
                                                     ['nodeType'])
        node_dict[node_id] = node['name']
        #Loop through deadnets to get those IPs as well
        for v_net in node['virtualNetworks']:
            net_id = v_net['virtualNetworkID']
            if net_id in virt_net_dict.keys():
                vlan_tag = str(virt_net_dict[net_id])
                virt_net_add = v_net['address']
                out_dict['Node ID ' + node_id + ' VLAN ' + vlan_tag +
                         ' address'] = virt_net_add
        node_count = node_count + 1
    if node_count != 0:
        out_dict['----------------'] = '----------------'
    out_dict['Total nodes'] = node_count
    hdr1 = 'Active base information'
    hdr2 = 'Output'
    return hdr1, hdr2, out_dict, node_dict


def get_pending_active_nodes(**output_dict):
    """
    Get the pending active node information, no deadnet info is available
    """
    out_dict = {}
    node_count = 0
    response_json = output_dict['ListPendingActiveNodes']
    for node in response_json['result']['pendingActiveNodes']:
        node_id = str(node['nodeID'])
        out_dict['------Node ID ' + node_id + ' ------'] = \
            '--------------------------'
        out_dict['Node ID ' + node_id + ' name'] = (node['name'])
        out_dict['Node ID ' + node_id + ' management IP'] = (node['mip'])
        out_dict['Node ID ' + node_id + ' storage IP'] = (node['sip'])
        out_dict['Node ID ' + node_id + ' version'] = (node['softwareVersion'])
        out_dict['Node ID ' + node_id + ' model'] = (node['platformInfo']
                                                     ['nodeType'])
        node_count = node_count + 1
    if node_count != 0:
        out_dict['----------------'] = '----------------'
    out_dict['Total nodes'] = node_count
    hdr1 = 'Pending Active Node Configuration'
    hdr2 = 'Setting'
    return hdr1, hdr2, out_dict


def get_pending_nodes(**output_dict):
    """
    Get the pending node information, no deadnet info is available
    """
    out_dict = {}
    node_count = 0
    response_json = output_dict['ListPendingNodes']
    for node in response_json['result']['pendingNodes']:
        node_id = str(node['pendingNodeID'])
        out_dict['------Node ID ' + node_id + ' ------'] = \
            '--------------------------'
        out_dict['Node ID ' + node_id + ' name'] = (node['name'])
        out_dict['Node ID ' + node_id + ' management IP'] = (node['mip'])
        out_dict['Node ID ' + node_id + ' storage IP'] = (node['sip'])
        out_dict['Node ID ' + node_id + ' version'] = (node['softwareVersion'])
        out_dict['Node ID ' + node_id + ' model'] = (node['platformInfo']
                                                     ['nodeType'])
        node_count = node_count + 1
    if node_count != 0:
        out_dict['----------------'] = '----------------'
    out_dict['Total nodes'] = node_count
    hdr1 = 'Pending Node Configuration'
    hdr2 = 'Setting'
    return hdr1, hdr2, out_dict


def get_drives(**output_dict):
    """
    Get all the drives, break them out by status and type for display
    """
    out_dict = {}
    active_drive_count = 0
    pending_drive_count = 0
    block_drive_count = 0
    volume_drive_count = 0
    failed_drive_count = 0
    response_json = output_dict['ListDrives']
    for drive in response_json['result']['drives']:
        if drive['status'] == 'active':
            active_drive_count = active_drive_count + 1
        elif drive['status'] == 'available':
            pending_drive_count = pending_drive_count + 1
        else:
            failed_drive_count = failed_drive_count + 1
        if drive['type'] == 'block':
            block_drive_count = block_drive_count + 1
        else:
            volume_drive_count = volume_drive_count + 1
        out_dict['Drive size'] = str(round(
            (drive['capacity']/1000/1000/1000/1000), 2)) + 'TB'
    out_dict['Active drive count'] = active_drive_count
    out_dict['Pending drive count'] = pending_drive_count
    out_dict['Failed drive count'] = failed_drive_count
    out_dict['Block drive count'] = block_drive_count
    out_dict['Volume drive count'] = volume_drive_count
    hdr1 = 'Drive information'
    hdr2 = 'Output'
    return hdr1, hdr2, out_dict


def get_ntp_info(**output_dict):
    """
    Gets NTP info, seriously that is all it does
    """
    out_dict = {}
    ntp_count = 0
    response_json = output_dict['GetNtpInfo']
    #Loop through possible multiple NTP hosts and output each as a unique item
    for server in response_json['result']['servers']:
        out_dict['NTP server ' + str(ntp_count)] = server
        ntp_count = ntp_count + 1
    hdr1 = 'NTP Configuration'
    hdr2 = 'NTP server'
    return hdr1, hdr2, out_dict


def get_snmp_trap_info(**output_dict):
    """
    Gets SNMP info, seriously that is all it does
    """
    out_dict = {}
    traphost_count = 0
    response_json = output_dict['GetSnmpTrapInfo']
    # print(json.dumps(response_json, sort_keys=True, indent=4))
    snmp_cls_evt_trap_enabled = (response_json['result']
                                 ['clusterEventTrapsEnabled'])
    snmp_fault_resolved_trap_enabled = (response_json['result']
                                        ['clusterFaultResolvedTrapsEnabled'])
    snmp_fault_traps_enabled = (response_json['result']
                                ['clusterFaultTrapsEnabled'])
    out_dict['Event traps enabled'] = snmp_cls_evt_trap_enabled
    out_dict['Fault resolved enabled'] = snmp_fault_resolved_trap_enabled
    out_dict['Fault traps enabled'] = snmp_fault_traps_enabled
    #Loop through possible multiple traphosts and output each as a unique item
    for traphost in response_json['result']['trapRecipients']:
        out_dict['Host_' + str(traphost_count)] = traphost['host']
        out_dict['Community_' + str(traphost_count)] = traphost['community']
        out_dict['port_' + str(traphost_count)] = traphost['port']
        traphost_count = traphost_count + 1
    hdr1 = 'SNMP Option'
    hdr2 = 'Setting'
    return hdr1, hdr2, out_dict


def get_ldap_configuration(**output_dict):
    """
    Get the LDAP Configuration, not the users, just the Configuration
    """
    out_dict = {}
    response_json = output_dict['GetLdapConfiguration']
    denied_error = "xPermissionDenied"
    if 'result' not in response_json.keys() and denied_error in response_json:
        print("No data returned from GetLdapConfiguration.\n"
              "Permission was denied, is the account a cluster admin?\n")
        hdr1 = 'LDAP Configuration'
        hdr2 = 'Response'
        out_dict['Access Denied'] = 'Verify login credentials'
        return hdr1, hdr2, out_dict
    else:
        ldap_result = response_json['result']['ldapConfiguration']
        auth_type = ldap_result['authType']
        ldap_enabled = ldap_result['enabled']
        group_search_base_dn = ['groupSearchBaseDN']
        group_search_filter = ['groupSearchCustomFilter']
        group_search_type = ['groupSearchType']
        out_dict['Auth type'] = auth_type
        out_dict['Enabled'] = ldap_enabled
        out_dict['Group search base DN'] = group_search_base_dn
        out_dict['Group search filter'] = group_search_filter
        out_dict['Group search type'] = group_search_type
        if auth_type == 'SearchAndBind':
            bind_dn = ldap_result['searchBindDN']
            ldap_servers = ldap_result['serverURIs']
            user_search_base = ldap_result['userSearchBaseDN']
            user_search_filter = ldap_result['userSearchFilter']
            out_dict['BindDN'] = bind_dn
            out_dict['server list'] = ldap_servers
            out_dict['User search base'] = user_search_base
            out_dict['User search filter'] = user_search_filter

        hdr1 = 'LDAP option'
        hdr2 = 'Setting'
        return hdr1, hdr2, out_dict

def parse_network_info(net_bond, response_json):
    """
    Build the network info
    """
    out_dict = {}
    ip_list = []
    node_count = 0
    #Build individual node information
    for node_result in response_json['result']['nodes']:
        for node in response_json['result']['nodes']:
            if node['nodeID'] == node_result['nodeID']:
                node_id = str(node_result['nodeID'])
                n_id = "Node ID " + node_id
                net_result = node['result']['network'][net_bond]
                bond_addr = net_result['address']
                bond_mask = net_result['netmask']
                bond_gateway = net_result['gateway']
                bond_mode = net_result['bond-mode']
                bond_mtu = net_result['mtu']
                bond_speed = net_result['linkSpeed']
                name_servers = net_result['dns-nameservers']
                search_domains = net_result['dns-search']
                out_dict['------' + n_id + ' ------'] = \
                    '--------------------------'
                out_dict[n_id + ' Bond name'] = net_bond
                out_dict[n_id + ' Address'] = bond_addr
                out_dict[n_id + ' Netmask'] = bond_mask
                out_dict[n_id + ' Gateway'] = bond_gateway
                out_dict[n_id + ' Bond mode'] = bond_mode
                out_dict[n_id + ' MTU'] = bond_mtu
                out_dict[n_id + ' Link speed'] = bond_speed
                if net_bond == 'Bond1G':
                    out_dict[n_id + ' DNS servers'] = name_servers
                    out_dict[n_id + ' DNS search'] = search_domains
                    ip_list.append(bond_addr)
        node_count = node_count + 1
    if net_bond != 'Bond10G':
        return out_dict, ip_list
    else:
        return out_dict


def get_10g_network(**output_dict):
    """
    Get all of the storage network info: bond, address,
        mode, speed, dns, mtu, net, gateway, and routing info
    """
    response_json = output_dict['GetNetworkConfig']
    net_bond = 'Bond10G'
    out_dict = parse_network_info(net_bond, response_json)
    hdr1 = 'Storage Network information'
    hdr2 = 'Setting'
    return hdr1, hdr2, out_dict


def get_1g_network(**output_dict):
    """
    Get all of the management network info: bond, address,
        mode, speed, dns, mtu, net, gateway, and routing info
    """
    net_bond = 'Bond1G'
    response_json = output_dict['GetNetworkConfig']
    out_dict, ip_list = parse_network_info(net_bond, response_json)
    hdr1 = 'Management Network information'
    hdr2 = 'Setting'
    return hdr1, hdr2, out_dict, ip_list


def get_virtual_network_info(**output_dict):
    """
    Get the VLAN information including name,
        the svip ip, netmask, size, and starting IP
    """
    out_dict = {}
    response_json = output_dict['ListVirtualNetworks']
    # print(json.dumps(response_json, sort_keys=True, indent=4))
    for virtnet in response_json['result']['virtualNetworks']:
        vlan = str(virtnet['virtualNetworkTag'])
        #vlan_id = virtnet['virtualNetworkID']
        out_dict['-----VLAN ' + vlan + '-----'] = '--------------'
        out_dict[vlan + ' name'] = virtnet['name']
        out_dict[vlan + ' SVIP'] = virtnet['svip']
        out_dict[vlan + ' netmask'] = virtnet['netmask']
        for block in virtnet['addressBlocks']:
            out_dict[vlan + ' start'] = block['start']
            out_dict[vlan + ' size'] = block['size']
    hdr1 = 'Virtual network info'
    hdr2 = 'Settings'
    return hdr1, hdr2, out_dict


def get_ssh_info(**output_dict):
    """
    Get the SSH status of each node
    """
    out_dict = {}
    response_json = output_dict['GetClusterSshInfo']
    if 'result' not in response_json.keys():
        if 'xPermissionDenied' in response_json['error']['message']:
            print("No data returned from GetClusterSshInfo.\n"
                  "Permission denied, is the account a cluster admin?\n")
            out_dict['Access Denied'] = 'Verify login credentials'
        elif 'xUnknownAPIMethod' in response_json['error']['message']:
            print("Incorrect API version, SSH requires at least 10.3")
            out_dict['Unknown API'] = 'Verify API version 10.3 or above called'
        else:
            api_error = response_json['error']
            print("Error returned:\n{}".format(api_error))
            api_error_name = api_error['name']
            api_error_message = api_error['message']
            out_dict[api_error_name] = api_error_message
        hdr1 = 'SSH status'
        hdr2 = 'Response'
        return hdr1, hdr2, out_dict
    else:
        cls_status = response_json['result']['enabled']
        out_dict['Cluster'] = cls_status
        for node in response_json['result']['nodes']:
            node_id = str(node['nodeID'])
            ssh_state = node['enabled']
            out_dict[node_id] = ssh_state
        hdr1 = "Node ID"
        hdr2 = "SSH status"
        return hdr1, hdr2, out_dict


def list_cluster_admins(**output_dict):
    """
    List out the accounts declared as cluster admins
    Display if they are locally defined or from LDAP
    """
    out_dict = {}
    response_json = output_dict['ListClusterAdmins']
    if 'result' not in response_json.keys() and \
        "xPermissionDenied" in response_json['error']['message']:
        print("No data returned from ListClusterAdmins.\n"
              "Permission denied, is the account a cluster admin?\n")
        hdr1 = 'Cluster Admins'
        hdr2 = 'Response'
        out_dict['Access Denied'] = 'Verify login credentials'
        sort_order = None
        return hdr1, hdr2, out_dict, sort_order
    else:
        for admin in response_json['result']['clusterAdmins']:
            user_name = admin['username']
            auth_method = admin['authMethod']
            out_dict[user_name] = auth_method
        hdr1 = 'Username'
        hdr2 = 'Local or LDAP'
        sort_order = 2
        return hdr1, hdr2, out_dict, sort_order


def ping_node(ip_list):
    """
    Used to get the FQDN of the nodes and ping them, uncomment the line
    ping -c for *nix, uncomment the line ping -n for windows
    """
    out_dict = {}
    if system_name().lower() == "windows":
        ping_cmd = 'ping -n 1 '
        ping_out = ' > NUL'
    else:
        ping_cmd = 'ping -c 1 '
        ping_out = ' > /dev/null'
    for node_ip in ip_list:
        try:
            node_fqdn = (socket.gethostbyaddr(node_ip))[0]
            response = os.system(ping_cmd + node_fqdn + ping_out)
            if response == 0:
                out_dict[node_fqdn] = "Ping succeeded"
            else:
                out_dict[node_fqdn] = "Ping failed"
        except Exception:
            not_found = "Address " + node_ip + " not found in DNS, skipping."
            out_dict[node_ip] = not_found
    hdr1 = "Node FQDN"
    hdr2 = "Ping status"
    sort_order = 1
    return hdr1, hdr2, out_dict, sort_order

def build_table(hdr1, hdr2, out_dict, filename, sort_order=None):
    """
    Builds the table outputs and writes them to a file
    """
    out_tbl = PrettyTable()
    out_tbl.field_names = (hdr1, hdr2)
    out_tbl.align[hdr1] = 'l'
    out_tbl.align[hdr2] = 'l'
    for key, value in out_dict.items():
        out_tbl.add_row([key, value])
    out_tbl_text = out_tbl.get_string()
    if sort_order == 1:
        print(out_tbl.get_string(sortby=hdr1))
    elif sort_order == 2:
        print(out_tbl.get_string(sortby=hdr2))
    else:
        print(out_tbl)
    with open(filename, 'a') as file:
        file.write(out_tbl_text + "\n")
    print("\n\n")


def get_filename(mvip):
    """
    Build the output filename
    """
    mydate = datetime.datetime.now()
    outdate = mydate.strftime("%Y-%m-%d")
    filename = mvip + '_irc_checklist_out_' + outdate + '.txt'
    if os.path.exists(filename):
        os.remove(filename)
    print('Output file name is: {}'.format(filename))
    return filename


def main():
    """
    Run the functions created above
    """
    input_tuple = get_inputs()
    mvip = input_tuple[0]
    user = input_tuple[1]
    user_pass = input_tuple[2]
    filename = get_filename(mvip)
    headers, url = build_auth(mvip,
                              user,
                              user_pass)
    output_dict = get_outputs(headers,
                              url)
    hdr1, hdr2, out_dict = get_cluster_info(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_drives(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_cluster_capacity(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_cluster_version(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_cluster_pairs(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_snmp_trap_info(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_ntp_info(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_virtual_network_info(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    active_nodes_tuple = get_active_nodes(**output_dict)
    hdr1 = active_nodes_tuple[0]
    hdr2 = active_nodes_tuple[1]
    out_dict = active_nodes_tuple[2]
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_pending_nodes(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_pending_active_nodes(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_10g_network(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict, ip_list = get_1g_network(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict = get_ldap_configuration(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)
    hdr1, hdr2, out_dict, sort_order = list_cluster_admins(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename,
                sort_order)
    hdr1, hdr2, out_dict, sort_order = ping_node(ip_list)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename,
                sort_order)
    hdr1, hdr2, out_dict = get_ssh_info(**output_dict)
    build_table(hdr1,
                hdr2,
                out_dict,
                filename)

if __name__ == '__main__':
    main()
