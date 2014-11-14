#!/bin/bash
##################################################################
# profiletool.sh is a tool for automagically generating ACL
# profiles for zNcrypt. Also remember that each time an adjustment
# to configuration objects like log location and data directories
# *may* require an update of the stale ACL profiles. Just run this
# script again. The sed entries in the get_profiles function add 
# wildcard support so minor adjustments regarding memory utilization
# won't break the ACL rules.
##################################################################
#
# Author:: Dustin Warren (dustin.warren@cloudera.com)
# Copyright 2014, Cloudera
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
if [[ $(id -u) -ne 0 ]]; then
	printf '\x1b[31m Please execute this script as root or with sudo access.\x1b[0m\n'
	exit
fi
function print_banner {
    color="\x1b[32m"
    company_color="\x1b[34m"
    echo -e "$color
 _____         ___ _ _     _____         _
|  _  |___ ___|  _|_| |___|_   _|___ ___| |
|   __|  _| . |  _| | | -_| | | | . | . | |
|__|  |_| |___|_| |_|_|___| |_| |___|___|_|
        \x1b[0m Powered by$company_color Cloudera Inc.\x1b[0m (c) 2014"
}

function check_zncrypt {
    if [[ -f /usr/sbin/zncrypt ]]; then
        echo -n "Type MASTER passphrase: "
        read -s zpass
        printf "\n"
        echo -n "Enter the ACL category you created (include the @ symbol): "
        read category
        printf "\n"
    else
        echo "zNcrypt is not installed....Exiting"
        echo "Please install zNcrypt prior to proceeding with this script"
        exit 1
    fi
}

function get_profiles {
	nn=`pgrep -f org.apache.hadoop.hdfs.server.namenode.NameNode`
	sn=`pgrep -f org.apache.hadoop.hdfs.server.namenode.SecondaryNameNode`
	dn=`pgrep -f org.apache.hadoop.hdfs.server.datanode.DataNode`
	#yarn_nodemanager=`pgrep -f org.apache.hadoop.yarn.server.nodemanager.NodeManager` # not implemented
        #hive2=`pgrep -f org.apache.hive.service.server.HiveServer2` # not implemented
    echo "[+] One moment while we generate ACL profiles for running processes...."
	if [[ -z $nn ]] ; then
	        unset $nn
	else
		echo "***Generating ACL profile for NameNode***"
		/usr/sbin/zncrypt-profile -p $nn > /tmp/nn.prof
		sed -i 's/-Xmx[0-9]*m /-Xmx## /g' /tmp/nn.prof
		sed -i 's/-Xmx[0-9]*./-Xmx## /g' /tmp/nn.prof
		sed -i 's/ # / /' /tmp/nn.prof
		sed -i 's/-Xms[0-9]*/-Xms##/g' /tmp/nn.prof
	fi
	if [[ -z $sn ]] ; then
	        unset $sn
	else
		echo "***Generating ACL profile for Secondary NameNode***"
	        /usr/sbin/zncrypt-profile -p $sn > /tmp/sn.prof
                sed -i 's/-Xmx[0-9]*m /-Xmx## /g' /tmp/sn.prof
                sed -i 's/-Xmx[0-9]*./-Xmx## /g' /tmp/sn.prof
                sed -i 's/ # / /' /tmp/sn.prof
                sed -i 's/-Xms[0-9]*/-Xms##/g' /tmp/sn.prof
	fi
	if [[ -z $dn ]] ; then
	        unset $dn
	else
		echo "***Generating ACL profile for DataNode***"
	        /usr/sbin/zncrypt-profile -p $dn > /tmp/dn.prof
                sed -i 's/-Xmx[0-9]*m /-Xmx## /g' /tmp/dn.prof
                sed -i 's/-Xmx[0-9]*./-Xmx## /g' /tmp/dn.prof
                sed -i 's/ # / /' /tmp/dn.prof
                sed -i 's/-Xms[0-9]*/-Xms##/g' /tmp/dn.prof
	fi
}

function set_profile_nn {
    if [[ -f /tmp/nn.prof ]]; then
        echo "[+] Adding ACL for NameNode...."
        nn_bin=$(grep cmdline /tmp/nn.prof| awk {'print $1'}| cut -d : -f2| tr -d \")
        printf $zpass | /usr/sbin/zncrypt acl --add --rule "ALLOW $category * $nn_bin" --profile-file /tmp/nn.prof &>/dev/null
        rm -f /tmp/nn.prof
    fi
}

function set_profile_sn {
    if [[ -f /tmp/sn.prof ]]; then
        echo "[+] Adding ACL for Secondary NameNode...."
        sn_bin=$(grep cmdline /tmp/sn.prof| awk {'print $1'}| cut -d : -f2| tr -d \")
        printf $zpass | /usr/sbin/zncrypt acl --add --rule "ALLOW $category * $sn_bin" --profile-file /tmp/sn.prof &>/dev/null
        rm -f /tmp/sn.prof
    fi
}

function set_profile_dn {
    if [[ -f /tmp/dn.prof ]]; then
        echo "[+] Adding ACL for DataNode...."
        dn_bin=$(grep cmdline /tmp/dn.prof| awk {'print $1'}| cut -d : -f2| tr -d \")
        printf $zpass | /usr/sbin/zncrypt acl --add --rule "ALLOW $category * $dn_bin" --profile-file /tmp/dn.prof &>/dev/null
        rm -f /tmp/dn.prof
    fi
}
# cake is delicious!
print_banner
check_zncrypt
get_profiles
set_profile_nn
set_profile_sn
set_profile_dn
