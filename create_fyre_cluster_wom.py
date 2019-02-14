#!/usr/bin/python
#
# This script will create a set of VM that meets the WDP-Installer.sh needs
# It will generate the required conf file for you to script out the entire process
#
import os
import sys
from os.path import expanduser
import paramiko
import time
import json
from threading import Thread

import warnings
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


# Global variables...
debug_mode = False
num_master = 3
num_compute = 0
num_storage = 0
num_deploy = 2
three_node = False
max_mem_cpu = False
mergeStorage = True
deploy_data = {}

proxy_ip = ""
proxy_ip_from_database = False
balancer_ip = {}
balancer_id = "ip"
deploy_os_name = "redhat"
deploy_os_ver = "7.4"
platform = "x"
cluster_information_ip_pass = []
node_hostName = []
parted_ip_list = []
one_partition = False
load_balance = False
external_access = False
selinux_mode = "permissive"
conf_file = "wdp.conf"
use_nfs = False
nfs_server = {}
for_auto_test = False

#Docker disk
docker_partition = False
docker_partition_size = 500

# Dictionaries for disks populated in get_create_json and for getting partition sizes in node_config
disks = {}

# Constants
FYRE_URL = "https://api.fyre.ibm.com/rest/v1/"
PROXY_REQUEST_URL = "http://mavin1.fyre.ibm.com/requestStaticIP"
PROXY_GET_IP_URL = "http://mavin1.fyre.ibm.com/requestProxyIPbyName"

DEV_CONF_FILE = "wdp_dev.conf"
SSH_KEY_FILE = expanduser("~") + "/.ssh/id_rsa.pub"
SSH_OPTS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
NTP_SERVERS = {'svl':'fintpsvl1p.fyre.ibm.com', 'not_svl':'fintpsvl1.fyre.ibm.com'}

#Disk partition script
part_disk_script_name = "dsx_part_script"
part_disk_script = """#!/bin/bash
if [[ $# -ne 2 ]]; then
    echo "Requires a mounted path name and size of the disk"
    echo "$(basename $0) <path> <size>"
    exit 1
fi
set -e
disks=$(lsblk | grep ${2}G | grep disk| awk '{print $1;}')
count_disks=$(lsblk | grep ${2}G| grep disk| awk '{print $1;}' | wc -l)
if [[ ${1} == "/ibm" ]]; then
    if [[ ${2} == "250" ]]; then
        for (( c=1; c<=$count_disks; c++ ))
        do
            candidate_disk=$(echo "$disks" | sed -n "${c}"p)
            free_disk=$(lsblk | grep ${candidate_disk} | grep part | awk '{print $1;}')
            if [[ $free_disk == "" ]]; then
                disk=${candidate_disk}
                break
            fi
        done
    else
        disk=$(echo "$disks" | sed -n "1"p)
    fi
elif [[ ${1} == "/data" ]]; then
    disk=$(echo "$disks" | sed -n "${count_disks}"p)
else
    echo "Please enter /ibm for install path or /data for data path"
    exit 1
fi
parted /dev/${disk} --script mklabel gpt
sleep 3
parted /dev/${disk} --script mkpart primary '0%' '100%'
sleep 3
mkfs.xfs -f -n ftype=1 /dev/${disk}1
mkdir -p ${1}
part_uuid=$(blkid -s PARTUUID -o value /dev/${disk}1)
echo "PARTUUID=${part_uuid}       ${1}              xfs     defaults,noatime    1 2" >> /etc/fstab
mount ${1}
exit 0
"""

# ntp time sync setup script
ntp_setup_script_name = "ntp_setup"
ntp_setup_script = """#!/bin/bash
if [[ $# -ne 1 ]]; then
    echo "Requires an ntp server to sync to"
    echo "$(basename $0) <ntp_server>"
    exit 1
fi
set -e
sed -i "/^server .*$/d" /etc/ntp.conf
echo "server ${1} iburst" >> /etc/ntp.conf
systemctl enable ntpd
systemctl restart ntpd || systemctl start ntpd
exit 0
"""

ntp_setup_script_for_ubuntu = """#!/bin/bash
if [[ $# -ne 1 ]]; then
    echo "Requires an ntp server to sync to"
    echo "$(basename $0) <ntp_server>"
    exit 1
fi
set -e
sed -i "/^pool .*$/d" /etc/ntp.conf
echo "pool ${1} iburst" >> /etc/ntp.conf
systemctl enable ntp
systemctl restart ntp || systemctl start ntp
exit 0
"""

def write_part_script(name):
    global part_disk_script_name
    part_disk_script_name = part_disk_script_name + "_" + name
    file = open(part_disk_script_name, "w")
    file.writelines(part_disk_script)
    file.close()

def write_ntp_setup_script(name):
    global ntp_setup_script_name
    ntp_setup_script_name = ntp_setup_script_name + "_" + name
    file = open(ntp_setup_script_name, "w")
    if deploy_os_name == "ubuntu":
        file.writelines(ntp_setup_script_for_ubuntu)
    else:
        file.writelines(ntp_setup_script)
    file.close()

# Print this script usage and exit 1
def usage(msg):
    print("""
{}
Usage: {} --user=<fyre_user> --key=<fyre_api_key> --cluster=<cluster_name> [options]
Options:
    --num-master=n      Number of master nodes will be create, default is 3
    --num-storage=n     Number of storage nodes will be create, default is 3
    --num-compute=n     Number of compute nodes will be create, default is 3
    --num-deploy=n      Number of deploy nodes will be create, default is 0
    --9-nodes           Separate the storage and master nodes
    --os-name=os_name   Os name has to be in the list provided from https://fyre.svl.ibm.com/help#fyre-api (default is RHEL)
    --os-version=x.x    Os version, this and --os-name has to come together (default is 7.4 for RHEL)
    --3-nodes           Only create three master nodes with additional disk 1000, --num options will not take effective
    --max-mem-cpu       Only enable with --3-nodes flag. Create three master nodes with 16 CPU and 32G memory
    --one-partition     Using the same partition for data storage as the install
    --external-access   Creates wdp_dev.conf file containing master-1 public ip for installer to provide external web access
    --platform=<plat>   The platform architecture; either x for x86_64 or p for ppc64le or z for s390x (default is x86_64)
    --debug             Show more debug information
    --docker-raw-disk   add another disk for Device Mapper
    --load-balancer=<id>Add load balancer node with nginx setup, <id> can be either ip or fqdn
    --selinux-enforcing Set selinux to enforcing instead of permissive
    --nfs-server        Add NFS server node
    --auto-test         This flag is for automation install test, which calls configure_nodes, load balancer node and NFS server node will not reconfigured if the flag used
""".format(msg, sys.argv[0]))
    sys.exit(1)


# Print information if debug enabled
def log(msg):
    if debug_mode:
        print(msg)


def get_proxy_ip(url, account_info):
    data_post = {
        'username': account_info[0],
        'api_key': account_info[1],
        'cluster_name': account_info[2]
    }
    try:
        r = requests.post(url, data=json.dumps(data_post))
        if r.status_code == 200:
            data = r.json()
            log("Proxy Ip found")
            return data['message']
        else:
            data = r.json()
            print (data['message'])
            log("Proxy Ip request fail")
            return None
    except:
        log("Proxy Ip request fail")
        return None


# Send request to Fyre and get json response
def sendRequest(query, account_info, data=None):
    auth = (account_info[0], account_info[1])
    url = FYRE_URL + query
    log("Sending url: " + url)
    if (data is None):
        resp = requests.post(url, auth=auth, verify=False)
    else:
        resp = requests.post(url, data=data, auth=auth, verify=False)
    if resp.status_code != 200:
        print("Request getting non-ok code ({}): {}".format(resp.status_code, url))
        sys.exit(1)
    return resp.json()


# Validate the user arguments
def validate_args():
    account_info = ["", "", ""]
    has_set_os = 0

    if not os.path.isfile(SSH_KEY_FILE):
        print("The ssh public key file {} does not exist".format(SSH_KEY_FILE))
        sys.exit(1)

    if "--debug" in sys.argv[1:]:
        print("enabled")
        global debug_mode
        debug_mode = True

    global num_storage, mergeStorage, num_master,three_node, max_mem_cpu, \
        one_partition, external_access, load_balance, docker_partition, platform, num_compute
    for cur_arg in sys.argv[1:]:
        if cur_arg.startswith("--user="):
            if cur_arg == "--user=":
                usage("User name cannot be empty")
            account_info[0] = cur_arg[(cur_arg.index("=") + 1):]
            log("User name is " + account_info[0])
        elif cur_arg.startswith("--key="):
            if cur_arg == "--key=":
                usage("API key cannot be empty")
            account_info[1] = cur_arg[(cur_arg.index("=") + 1):]
            log("API key is " + account_info[1])
        elif cur_arg.startswith("--cluster="):
            if cur_arg == "--cluster=":
                usage("Cluster name cannot be empty")
            account_info[2] = cur_arg[(cur_arg.index("=") + 1):]
            log("Cluster name is " + account_info[2])
        elif cur_arg.startswith("--num-master="):
            num_master = validate_node_num("--num-master=", cur_arg)
            log("There will be %d master nodes" % (num_master))
        elif cur_arg.startswith("--num-storage="):
            num_storage = validate_node_num("--num-storage=", cur_arg)
            log("There will be %d storage nodes" % (num_storage))
        elif cur_arg.startswith("--num-compute="):
            num_compute = validate_node_num("--num-compute=", cur_arg)
            log("There will be %d compute nodes" % (num_compute))
        elif cur_arg.startswith("--num-deploy="):
            global num_deploy
            num_deploy = validate_node_num("--num-deploy=", cur_arg)
            log("There will be %d deploy nodes" % (num_deploy))
        elif cur_arg == "--9-nodes":
            num_storage = 0
            mergeStorage = False
            log("There will be 3 master/storage, 0 compute")
        elif cur_arg.startswith("--os-name="):
            global deploy_os_name
            deploy_os_name = cur_arg[(cur_arg.index("=") + 1):].lower()
            if deploy_os_name not in ["centos", "redhat", "ubuntu"]:
                usage("OS not supported, either CentOS, Redhat or Ubuntu.")
            log("OS will be {}".format(deploy_os_name))
            has_set_os += 1
        elif cur_arg.startswith("--os-version="):
            global deploy_os_ver
            deploy_os_ver = cur_arg[(cur_arg.index("=") + 1):]
            log("OS version will be {}".format(deploy_os_ver))
            has_set_os += 1
        elif cur_arg == "--3-nodes":
            three_node = True
            num_compute = 0
        elif cur_arg == "--max-mem-cpu":
            max_mem_cpu = True
        elif cur_arg == "--external-access":
            external_access = True
        elif cur_arg == "--one-partition":
            one_partition = True
        elif cur_arg == '--docker-raw-disk':
            docker_partition = True
        elif cur_arg.startswith("--load-balancer="):
            if cur_arg.split("--load-balancer=")[1] not in ["ip", "fqdn"]:
                usage("Wrong Load balancer identity, either ip or fqdn")
            load_balance = True
            global balancer_id
            balancer_id = cur_arg[(cur_arg.index("=") + 1):]
            log("Load balancer identity will be {}".format(balancer_id))
        elif cur_arg.startswith("--platform="):
            platform = cur_arg[(cur_arg.index("=") + 1):]
            if platform not in ["x", "p", "z"]:
                usage("Wrong platform, either x, p or z")
        elif cur_arg.startswith("--debug"):
            pass
        elif cur_arg.startswith("--selinux-enforcing"):
            global selinux_mode
            selinux_mode = "enforcing"
        elif cur_arg == "--nfs-server":
            global use_nfs
            use_nfs = True
        elif cur_arg == "--auto-test":
            global for_auto_test
            for_auto_test = True
        else:
            usage("Unrecongized parameter '%s'" % (cur_arg))

    if has_set_os == 1:
        usage("--os-name= and --os-version= has to be appear both or none")

    # ppc64le(p) and s390x(z) not supported on CentOS
    if deploy_os_name == "centos" and platform in ["p", "z"]:
        usage("ppc64le and s390x currently not supported on CentOS")

    for i in account_info:
        if i is None or i == "":
            usage("Missing required parameter")

    return account_info


# When user specify a number for nodes, make sure it is valid
def validate_node_num(param, user_input):
    if param == user_input:
        usage("Parameter {} needs to come with a number".format(param))
    num_str = user_input[(user_input.index("=") + 1):]
    paramStr = user_input[:(user_input.index("=") + 1)]
    try:
        my_num = int(num_str)
        if (my_num < 3 and paramStr != "--num-deploy="):
            if three_node and paramStr == "--num-compute=":
                return my_num
            usage("Parameter {} must have a value greather than or equal to 3".format(param))
        return my_num
    except ValueError:
        usage("Parameter {} has the non-interger value".format(param))


# Generate a json
def get_create_json(account_info):
    f = open(SSH_KEY_FILE, 'r')
    key = f.readline()
    key = key.rstrip('\n')
    f.close()

    deploy_os = "{} {}".format(deploy_os_name, deploy_os_ver)
    data = {
        "fyre": {
            "creds": {
                "username": account_info[0],
                "api_key": account_info[1],
                "public_key": key
            }
        },
        "clusterconfig": {
            "instance_type": "virtual_server",
            "platform": platform
        },
        "cluster_prefix": account_info[2],
        account_info[2]: []
    }
    nodes = []

    proxy_node = FyreNodeJson(name="Proxy", count=1, cpu=1, memory=1, os=deploy_os, publicvlan="n", privatevlan="y",additional_disks=[])
    proxy_ip_temp = get_proxy_ip(PROXY_REQUEST_URL, account_info)
    if not proxy_ip_temp is None:
        global proxy_ip_from_database,proxy_ip
        proxy_ip_from_database = True
        proxy_ip = proxy_ip_temp
        proxy_node = None

    if not proxy_node is None:
        nodes.append(proxy_node)

    global disks
    if three_node:
        disks = {"master": [{"size": 100}, {"size": 100}], "compute":  [{"size": 250}], "deploy": [{ "size": 600}]}
        if max_mem_cpu:
            cpu=16
            mem=32
        else:
            cpu=8
            mem=24
        if docker_partition:
            for type, disk in disks.iteritems():
                disk.append({"size": docker_partition_size})
        nodes.append(FyreNodeJson(name="Master-1", count=1, cpu=cpu, memory=mem, os=deploy_os, publicvlan="y", privatevlan="y", additional_disks=disks["master"]))
        nodes.append(FyreNodeJson(name="Master-2", count=1, cpu=cpu, memory=mem, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["master"]))
        nodes.append(FyreNodeJson(name="Master-3", count=1, cpu=cpu, memory=mem, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["master"]))
        if num_deploy > 0:
             for x in range(1, num_deploy + 1):
                 nodes.append(FyreNodeJson(name="Deploy-{}".format(x), count=1, cpu=24, memory=64, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["deploy"]))
        if num_compute > 0:
             for x in range(1, num_compute + 1):
                 nodes.append(FyreNodeJson(name="Compute-{}".format(x), count=1, cpu=8, memory=32, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["compute"]))
    else:
        disks = {
            "master": [{ "size": 100}],
            "storage": [{ "size": 400}, {"size": 400}],
            "compute":  [{"size": 250}],
            "deploy": [{ "size": 600}]
        }
        if mergeStorage:
            disks["master"] = [{"size": 100}, {"size": 100}]
            if docker_partition:
                for type, disk in disks.iteritems():
                    disk.append({"size": docker_partition_size})

            nodes.append(FyreNodeJson(name="Master-1", count=1, cpu=4, memory=4, os=deploy_os, publicvlan="y", privatevlan="y", additional_disks=disks["master"]))
            for x in range(2, num_master + 1):
                nodes.append(FyreNodeJson(name="Master-{}".format(x), count=1, cpu=4, memory=4, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["master"]))
        if num_storage > 0:
            nodes.append(FyreNodeJson(name="Storage", count=num_storage, cpu=8, memory=32, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["storage"]))
        if num_deploy > 0:
             for x in range(1, num_deploy + 1):
                 nodes.append(FyreNodeJson(name="Deploy-{}".format(x), count=1, cpu=24, memory=64, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["deploy"]))
        nodes.append(FyreNodeJson(name="Compute", count=num_compute, cpu=8, memory=32, os=deploy_os, publicvlan="n", privatevlan="y", additional_disks=disks["compute"]))
    global load_balance, use_nfs
    if load_balance:
        nodes.append(FyreNodeJson(name="balancer", count=1, cpu=2, memory=4, os=deploy_os, publicvlan="y", privatevlan="y"))
    if use_nfs:
        nodes.append(FyreNodeJson(name="nfs-server", count=1, cpu=2, memory=4, os=deploy_os, publicvlan="n", privatevlan="y"))
    data[account_info[2]] = nodes
    string = json.dumps(data, indent=4, separators=(',', ': '))
    log("============= Create request ==================")
    log(string)
    log("===============================================")
    return string

def FyreNodeJson(name, count, cpu, memory, os, publicvlan, privatevlan, additional_disks=[]):
    m = {
        "name": name,
        "count": count,
        "cpu": cpu,
        "memory": memory,
        "os": os,
        "publicvlan": publicvlan,
        "privatevlan": privatevlan,
        "additional_disks": additional_disks
    }
    return m


# Create the cluster
def create_cluster(account_info):
    # Check if the cluster name is exist already
    res = sendRequest("?operation=query&request=showclusters", account_info)
    cluster_list = res.get("clusters")
    if res.has_key("status"):
        print("Unexpected result for request showclusters")
        print("=====================================================")
        print("{}: {}".format(res.get("status"), res.get("details")))
        print("=====================================================")
        sys.exit(1)
    for c_info in cluster_list:
        if (c_info.get("name") == account_info[2]):
            print("The cluster name is already exist in your account")
            sys.exit(1)
    log("The cluster name {} is valid for create".format(account_info[2]))

    # Create now
    print("Submit create VM request to fyre and wait for completion")
    res = sendRequest("?operation=build", account_info, data=get_create_json(account_info))
    req_id = res.get("request_id")
    print("Create request id is {}".format(req_id))

    # Loop to check the building is done
    while True:
        res = sendRequest("?operation=query&request=showrequests&request_id=" + req_id, account_info)
        req_list = res.get("request")
        req_info = req_list[0]
        req_status = req_info.get("status")
        if req_status == "error":
            print("Failed to create cluster due to: {}".format(req_info.get("error_details")))
            sys.exit(1)
        elif req_status == "new":
            log("Still in new state")
        elif req_status == "building":
            log("Still in building state")
        elif req_status == "completed":
            log("Completed state right now!")
            if req_info.get("error_details") != "0":
                print("Create completed with error: {}".format(req_info.get("error_details")))
                sys.exit(1)
            break
        else:
            print("Unrecognized create status: {}".format(req_status))
            sys.exit(1)

        time.sleep(5)

    # Return the cluster info
    res = sendRequest("?operation=query&request=showclusterdetails&cluster_name=" + account_info[2], account_info)
    if not res.has_key(account_info[2]):
        print("Invalid response when getting information for cluster {}".format(account_info[2]))
        print("=====================================================")
        print(str(res))
        print("=====================================================")
        sys.exit(1)
    return res


# Creating the configuration file according to the fyre api response
def create_file(cluster_info):
    global cluster_information_ip_pass, parted_ip_list, deploy_data, proxy_ip, node_hostName, balancer_id, load_balance, use_nfs, balancer_ip, nfs_server
    field, clus_info = cluster_info.items()[0]
    node_hostName = []
    for l in clus_info:
        node_hostName.append(l["node"])

    global conf_file
    conf_file = "wdp." + field + ".conf"
    if os.path.exists(os.getcwd() + "/" + conf_file):
        os.remove(os.getcwd() + "/" + conf_file)
    f = open(os.getcwd() + "/" + conf_file, 'w')
    f.write("# Warning: This file generated by a script, do NOT share\n")
    f.write("user=root\n")
    proxy_ip = get_proxy_ip(PROXY_GET_IP_URL, ["", "", field])
    if not proxy_ip is None and not load_balance:
        f.write("virtual_ip_address={}\n".format(proxy_ip))
    for line in clus_info:
        node_info = line.get("node").split("-")
        if node_info[-1] == "proxy" and not load_balance and proxy_ip is None:
            proxy_ip = line.get("privateip")
            f.write("virtual_ip_address=%s\n" % (line.get("privateip")))
        elif node_info[-2] == "master":
            if three_node:
                f.write("node_%s=%s\n" % (node_info[-1], line.get("privateip")))
                if not use_nfs:
                    if one_partition:
                        f.write("node_data_%s=/ibm\n" % (node_info[-1]))
                    else:
                        f.write("node_data_%s=/data\n" % (node_info[-1]))
                f.write("node_path_%s=/ibm\n" % (node_info[-1]))
                parted_ip_list.append(line.get("privateip"))

            else:
                f.write("master_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
                f.write("master_node_path_%s=/ibm\n" % (node_info[-1]))
                if mergeStorage:
                    if not three_node and not use_nfs:
                        f.write("master_node_data_%s=/data\n" % (node_info[-1]))
                    parted_ip_list.append(line.get("privateip"))

            if node_info[-1] == "1":
                deploy_data = {"ip": line.get("publicip"), "password": line.get("root_password")}
                if external_access:
                    f_dev = open(os.getcwd() + "/" + DEV_CONF_FILE, 'w')
                    f_dev.write("EXTERNAL_IP=%s\n" % (deploy_data["ip"]))
                    f_dev.close()
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password"), "node": line.get("node")})
        elif node_info[-2] == "storage":
            f.write("storage_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
            if not use_nfs:
                if one_partition:
                    f.write("storage_node_data_%s=/ibm\n" % (node_info[-1]))
                else:
                    f.write("storage_node_data_%s=/data\n" % (node_info[-1]))
            f.write("storage_node_path_%s=/ibm\n" % (node_info[-1]))
            parted_ip_list.append(line.get("privateip"))
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password"), "node": line.get("node")})
        elif node_info[-2] == "compute":
            f.write("compute_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
            f.write("compute_node_path_%s=/ibm\n" % (node_info[-1]))
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password"), "node": line.get("node")})
        elif node_info[-2] == "deploy":
            f.write("deploy_node_%s=%s\n" % (node_info[-1], line.get("privateip")))
            f.write("deploy_node_path_%s=/ibm\n" % (node_info[-1]))
            cluster_information_ip_pass.append({"ip": line.get("privateip"), "password": line.get("root_password"), "node": line.get("node")})
        elif node_info[-1] == "balancer" and load_balance:
            if balancer_id == "ip":
                f.write("load_balancer_ip_address=%s\n" % (line.get("privateip")))
            elif balancer_id == "fqdn":
                f.write("load_balancer_fqdn=%s\n" % (line.get("node")))
            balancer_ip = {"ip": line.get("privateip"), "password": line.get("root_password"), "load_balancer_node_name": line.get("node")}
        elif node_info[-2] == "nfs" and node_info[-1] == "server" and use_nfs:
            nfs_server = {"ip": line.get("privateip"), "password": line.get("root_password"), "nfs_server_node_name": line.get("node")}
            f.write("nfs_server=%s\n" % (line.get("privateip")))
            f.write("nfs_dir=/data\n")
    f.write("ssh_port=22\n")
    f.write("overlay_network=10.17.0.0/16\n")
    f.write("suppress_warning=true\n")
    f.write("helm_request_timeout=14400\n")
    f.close()


# Wait for all nodes are running
def wait_all_running(account_info):
    for _ in range(60):
        res = sendRequest("?operation=query&request=showclusterdetails&cluster_name=" + account_info[2], account_info)
        if not res.has_key(account_info[2]):
            print("Invalid response when getting information for cluster {}".format(account_info[2]))
            print("=====================================================")
            print(str(res))
            print("=====================================================")
            sys.exit(1)
        cluster_info = res.get(account_info[2])

        is_all_running = True
        for line in cluster_info:
            if line.get("state") != "running":
                is_all_running = False
                break
        if is_all_running:
            print("All nodes are on running state")
            return
        time.sleep(5)
    print("Timeout to wait for all nodes to become running state")


# Set selinux, mount directory etc
def configure_nodes(account_info):
    global deploy_os_name
    write_part_script(account_info[2])
    write_ntp_setup_script(account_info[2])

    global ntp_server
    cluster_info = sendRequest("?operation=query&request=showclusterdetails&cluster_name=" + account_info[2], account_info)
    if cluster_info[account_info[2]][0]['site_name'] == 'svl':
        ntp_server = NTP_SERVERS['svl']
    else:
        ntp_server = NTP_SERVERS['not_svl']

    print("Configuring each node")
    threads = []
    for node_info in cluster_information_ip_pass:
        t = Thread(None, node_config, None, (deploy_data['ip'], node_info['ip'], deploy_data['password'], node_info['password'], node_info['node'], account_info))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    global load_balance, for_auto_test
    if load_balance and not for_auto_test:
        client, jhost = nested_ssh(deploy_data['ip'], balancer_ip['ip'], deploy_data['password'], balancer_ip['password'])
        load_balancer(deploy_data, balancer_ip, cluster_information_ip_pass, client, jhost)
    
    global use_nfs
    if use_nfs and not for_auto_test:
        client, jhost = nested_ssh(deploy_data['ip'], nfs_server['ip'], deploy_data['password'], nfs_server['password'])
        setup_nfs_server(deploy_data, nfs_server, cluster_information_ip_pass, client, jhost)

    if os.path.exists(os.getcwd() + "/part_disk.sh"):
        os.remove(os.getcwd() + "/part_disk.sh")

    # For Ubuntu cluster, no need to reboot because didn't change selinux
    if not deploy_os_name == "ubuntu":
        print("rebooting all nodes")
        for hostname in node_hostName:
            if not (hostname.endswith("nfs-server") and use_nfs) and not (hostname.endswith("balancer") and load_balance):
                if not hostname.endswith("-proxy"):
                    sendRequest("?operation=reboot&node_name={}".format(hostname), account_info)
                else:
                    sendRequest("?operation=shutdown&node_name={}".format(hostname), account_info)
        print("Intended sleep 60 seconds")
        time.sleep(60)
        wait_all_running(account_info)

    os.remove(part_disk_script_name)
    os.remove(ntp_setup_script_name)

def node_config(src_ip, dest_ip, src_pwd, dest_pwd, hostname, account_info):
    global deploy_os_name, platform
    client, jhost = nested_ssh(src_ip, dest_ip, src_pwd, dest_pwd)

    log("Copying partition script to " + dest_ip)
    ftp = jhost.open_sftp()
    f = ftp.put(part_disk_script_name, "part_disk.sh")
    if f is None:
        print("Unable to copy partition script")
        exit (1)
        sys.exit(1)

    log("Copying ntp setup script to " + dest_ip)
    ftp = jhost.open_sftp()
    f = ftp.put(ntp_setup_script_name, "ntp_setup.sh")
    if f is None:
        print("Unable to copy ntp setup script")
        exit (1)
        sys.exit(1)

    cmds = (
        "uuidgen > /etc/machine-id",
        "sed -i 's/.*net.ipv4.ip_forward.*/net.ipv4.ip_forward = 1/g' /etc/sysctl.conf >& /dev/null",
        "sysctl -p >& /dev/null",
    )

    global disks
    node_type = hostname.split("-")[-2].strip()
    log(hostname)
    if three_node:
        if node_type == "master":
            install_disk_size = disks["master"][0]["size"]
            data_disk_size = disks["master"][1]["size"]
        elif node_type in ["compute", "deploy"]:
            install_disk_size = disks[node_type][0]["size"]
            data_disk_size = disks[node_type][0]["size"]
        else:
            print("Host name not valid")
            sys.exit(1)
    else:
        if node_type == "master":
            install_disk_size = disks["master"][0]["size"]
            data_disk_size = disks["master"][0]["size"]
            if mergeStorage:
                install_disk_size = disks["master"][0]["size"]
                data_disk_size = disks["master"][1]["size"]
        elif node_type in ["storage", "compute", "deploy"]:
            install_disk_size = disks[node_type][0]["size"]
            data_disk_size = disks[node_type][0]["size"]
        else:
            print("Host name not valid")
            sys.exit(1)
    if deploy_os_name == "centos":
        add_on_cmds = (
            "yum install -y libselinux-python",
            "sed -i 's/^SELINUX=.*$/SELINUX=" + selinux_mode + "/g' /etc/selinux/config >& /dev/null",
            "chmod +x ~/part_disk.sh; ~/part_disk.sh /ibm " + str(install_disk_size) + "  >& /dev/null",
        )
    elif deploy_os_name == "redhat":
        add_on_cmds = (
            "yum install -y libselinux-python ntp nfs-utils",
            "sed -i 's/^SELINUX=.*$/SELINUX=" + selinux_mode + "/g' /etc/selinux/config >& /dev/null",
            "chmod +x ~/part_disk.sh; ~/part_disk.sh /ibm " + str(install_disk_size) + " >& /dev/null",
        )
    elif deploy_os_name == "ubuntu":
        add_on_cmds = (
            "echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections",
            "apt-get update",
            "apt-get install -y xfsprogs python curl ntp ntpstat ntpdate nfs-common",
            "systemctl stop systemd-resolved",
            "systemctl disable systemd-resolved",
            "systemctl mask systemd-resolved",
            "sed -i 's/search fyre.ibm.com/search fyre.ibm.com. svl.ibm.com./' /etc/resolv.conf >& /dev/null",
            "sed -i '/^nameserver .*$/d' /etc/resolv.conf",
            "echo 'nameserver 172.16.200.52' >> /etc/resolv.conf",
            "echo 'nameserver 172.16.200.50' >> /etc/resolv.conf",
            "chmod +x ~/part_disk.sh; ~/part_disk.sh /ibm " + str(install_disk_size) + " >& /dev/null",
        )
    else:
        print("OS not supported, either CentOS, Redhat or Ubuntu.")
    cmds = cmds + add_on_cmds + ("chmod +x ~/ntp_setup.sh; ~/ntp_setup.sh " + ntp_server + " >& /dev/null",)

    # Commands to be executed on all the nodes
    for cur_cmd in cmds:
        log("Node {} execute command: {} ".format(dest_ip, cur_cmd))
        _, stdout, stderr = jhost.exec_command(cur_cmd)
        if stdout.channel.recv_exit_status() != 0:
            print("Node {} execute command: {}\nStatus: {}\nOutput:\n{}\nError:\n{}".format(
                dest_ip, cur_cmd, str(stdout.channel.recv_exit_status()), str(stdout.readlines()), str(stderr.readlines())))
            exit(1)

    # For the storage nodes only
    if dest_ip in parted_ip_list:
        log("Executing partition script on {} for /data".format(dest_ip))
        _, stdout, stderr = jhost.exec_command("chmod +x ~/part_disk.sh; ~/part_disk.sh /data " + str(data_disk_size) + " >& /dev/null")
        log("Exit status:" + str(stdout.channel.recv_exit_status()))
        log("Command output: " + str(stdout.readlines()))
        if stdout.channel.recv_exit_status() != 0:
            print("Unable to execute partition script on {}".format(dest_ip))
            exit(1)

    # Do conf file scp on master -1
    if dest_ip == cluster_information_ip_pass[0]['ip']:
        log("Scp the wdp.conf file")
        f = ftp.put(conf_file, "/ibm/wdp.conf")
        if f is None:
            print("Failed to scp the conf file, please try again by yourself")
            sys.exit(1)
        if external_access:
            f = ftp.put(DEV_CONF_FILE, "/ibm/wdp_dev.conf")
            if f is None:
                print("Failed to scp the external access conf file, please try again by yourself")

        if balancer_id == "fqdn":
            _, master_1_host_name, stderr = jhost.exec_command("hostname -f")
            if master_1_host_name.channel.recv_exit_status() != 0:
                log("Error cannot get hostname from master 1")
                log("Command output: " + str(master_1_host_name.readlines()))
                exit(1)
            host = str(master_1_host_name.readlines()[0]).split('master-1')[1]
            load_balancer_fqdn = balancer_ip["load_balancer_node_name"] + host.strip()
            modify_wdp_conf_fqdn_cmd = "sed -i 's/^load_balancer_fqdn=.*$/load_balancer_fqdn=" + load_balancer_fqdn + "/g' /ibm/wdp.conf >& /dev/null"
            _, stdout, stderr = jhost.exec_command(modify_wdp_conf_fqdn_cmd)
            log("Exit status:" + str(stdout.channel.recv_exit_status()))
            if stdout.channel.recv_exit_status() != 0:
                log("Error modifying wdp.conf for load balancer FQDN")
                log("Command output: " + str(stdout.readlines()))
                exit(1)

    ftp.close()
    client.close()
    jhost.close()

def load_balancer(deploy_data, balancer_ip, cluster_information_ip_pass, client, jhost):
    log("Creating load balancer " + balancer_ip['ip'])
    wget_cmd = "wget https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm; yum install -y epel-release-latest-7.noarch.rpm; yum install -y nginx;"
    _, stdout, stderr = jhost.exec_command(wget_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Error in getting epel-release and installing nginx")
        log("Command output: " + str(stdout.readlines()))
        log("Command error: " + str(stderr.readlines()))
        exit(1)
        sys.exit(1)
    setup_conf_cmd = """mkdir -p /etc/nginx/tcpconf.d;
                       echo \"stream {
                                  upstream kubeapi {
                                      server %s:6443;
                                      server %s:6443;
                                      server %s:6443;
                                  }
                                  upstream dsxportal {
                                      server %s:443;
                                      server %s:443;
                                      server %s:443;
                                  }
                                  server {
                                      listen     6443;
                                      proxy_pass kubeapi;
                                  }
                                  server {
                                      listen     443;
                                      proxy_pass dsxportal;
                                  }
                              }\" > /etc/nginx/tcpconf.d/load-balancer.conf;""" % (cluster_information_ip_pass[0]['ip'], cluster_information_ip_pass[1]['ip'], cluster_information_ip_pass[2]['ip'], cluster_information_ip_pass[0]['ip'], cluster_information_ip_pass[1]['ip'],cluster_information_ip_pass[2]['ip'])
    _, stdout, stderr = jhost.exec_command(setup_conf_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Error in setup of load-balancer.conf")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
        sys.exit(1)
    include_conf_cmd = "sed -i '/include\ \/usr\/share\/nginx\/modules\/\*.conf/a include\ \/etc\/nginx\/tcpconf.d\/\*;' /etc/nginx/nginx.conf;"
    _, stdout, stderr = jhost.exec_command(include_conf_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Unable to copy the include command into nginx conf")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
        sys.exit(1)
    start_nginx_cmd = "systemctl enable nginx; systemctl start nginx"
    _, stdout, stderr = jhost.exec_command(start_nginx_cmd)
    log("Exit status:" + str(stdout.channel.recv_exit_status()))
    if stdout.channel.recv_exit_status() != 0:
        log("Error cannot enable or start nginx")
        log("Command output: " + str(stdout.readlines()))
        exit(1)
        sys.exit(1)

def setup_nfs_server(deploy_data, nfs_server, cluster_information_ip_pass, client, jhost):
    log("Creating NFS server on " + nfs_server['ip'])
    exports_content ="/data"
    for cluster_info in cluster_information_ip_pass:
        exports_content += " %s(rw,sync,no_root_squash)" % cluster_info['ip']
    log("exports_content: %s" % exports_content)
    if deploy_os_name == "ubuntu":
        cmds = (
            "mkdir -p /data",
            "apt install -y nfs-kernel-server",  
            "echo '"+ exports_content + "'| tee /etc/exports",
            "systemctl restart nfs-kernel-server"
        )
    else:
        cmds = (
            "mkdir -p /data",
            "yum install -y nfs-utils nfs-utils-lib", 
            "chkconfig nfs on", 
            "systemctl enable rpcbind",
            "systemctl enable nfs",
            "systemctl start rpcbind ", 
            "systemctl start nfs",
            "echo '"+ exports_content + "'| tee /etc/exports",
            "exportfs -a",
            "rpcinfo -p"
        )
    for cur_cmd in cmds:
        log("Node {} execute command: {} ".format(nfs_server['ip'], cur_cmd))
        _, stdout, stderr = jhost.exec_command(cur_cmd)
        if stdout.channel.recv_exit_status() != 0:
            print("Node {} execute command: {}\nStatus: {}\nOutput:\n{}\nError:\n{}".format(
                nfs_server['ip'], cur_cmd, str(stdout.channel.recv_exit_status()), str(stdout.readlines()), str(stderr.readlines())))
            exit(1)
            sys.exit(1)

# Connecting to the deploy node as jump server and then ssh to the target ip
def nested_ssh(levelOneIP, levelTwoIP, passwordIP1, passwordIP2):
    for count in range(11):
        log('trying to make ssh tunnel on {} number of try {}'.format(levelTwoIP, count))
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(levelOneIP, username='root', password=passwordIP1)
        vmtransport = client.get_transport()
        if vmtransport.is_active():
            vmchannel = vmtransport.open_channel("direct-tcpip", (levelTwoIP, 22), (levelOneIP, 22))
            jhost = paramiko.SSHClient()
            jhost.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            jhost.connect(levelTwoIP, username='root',password=passwordIP2, sock=vmchannel)
            if jhost.get_transport().is_active():
                return client, jhost
            else:
                jhost.close()
                client.close()
                log('Unable to connect to ' + levelTwoIP + ' through ' + levelOneIP + ' trying again')
                if count == 10:
                    exit(1)
                    sys.exit(1)
                time.sleep(10)
        elif count == 10:
            log('Unable to connect to ' + levelOneIP + ' through ssh with paramiko')
            exit(1)
            sys.exit(1)
        else:
            client.close()


# The script starts here
def run():
    print("Validating the the arguments")
    account_info = validate_args()

    if external_access:
        if os.path.isfile(os.getcwd() + "/" + DEV_CONF_FILE):
            print(
                "There is an external access configuration file with the same name {} in the directory already, please move them away and try again...".format(DEV_CONF_FILE))
            sys.exit(1)

    # Suppress warning message when sending insecure request
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # Ignoring the paramiko warning
    #   /usr/lib/python2.7/dist-packages/Crypto/Cipher/blockalgo.py:141: FutureWarning: CTR mode needs counter parameter, not IV
    warnings.simplefilter(action="ignore", category=FutureWarning)

    cluster_info = create_cluster(account_info)
    print("Request completed and generating the conf file")
    time.sleep(2)
    create_file(cluster_info)
    print("File generated")
    configure_nodes(account_info)
    print("Script finished successfully")

    os.remove(conf_file)
    sys.exit(0)


if __name__ == '__main__':
    run()