### todo
# Create tenant
# Create Site
## One Office 
## One Cloud 
# Create Vlans
# Don't create Cloud vlan or prefix
# Put in journal of Cloud mikrotik script
# Put in journal of office side mikrotik script




# cloud side

:global CustomerOfficeBigSubnet "10.201.40.0/21"

# Mikrotik Office side variables
:global NameDevice "CustomerName-City-Office"
:global AdminPassword "password
:global DnsServers "8.8.8.8,8.8.4.4,1.1.1.1"

:global InfraGWIp "10.201.40.1"
:global InfraIp "10.201.40.1/24"
:global InfraIpNetwork "10.201.40.0"
:global InfraIpSubnet "10.201.40.0/24"
:global PoolInfra "10.201.40.99-10.201.40.253"

:global OfficeGWIp "10.201.41.1"
:global OfficeIp "10.201.41.1/24"
:global OfficeIpNetwork "10.201.41.0"
:global OfficeIpSubnet "10.201.41.0/24"
:global PoolOffice "10.201.41.99-10.201.41.253"

:global VoipGWIp "10.201.42.1"
:global VoipIp "10.201.42.1/24"
:global VoipIpNetwork "10.201.42.0"
:global VoipIpSubnet "10.201.42.0/24"
:global PoolVoip "10.201.42.99-10.201.42.253"

:global SecurityGWIp "10.201.43.1"
:global SecurityIp "10.201.43.1/24"
:global SecurityIpNetwork "10.201.43.0"
:global SecurityIpSubnet "10.201.43.0/24"
:global PoolSecurity "10.201.43.99-10.201.43.253"

:global GuestGWIp "10.201.44.1"
:global GuestIp "10.201.44.1/24"
:global GuestIpNetwork "10.201.44.0"
:global GuestIpSubnet "10.201.44.0/24"
:global PoolGuest "10.201.44.99-10.201.44.253"

# statis data for client mikrotik side
:global OpenVPNClientName "OpenVPN_Cloud"
:global ServiceSubnet "10.200.110.0/24"
:global OpenVPNServerInterfaceIP "10.200.110.1"


# static variables for Server Alparslan side
:global OpenVPNProfileName "OpenVPN_Profile"


# Cloud Server and Client Office side variables
:global OpenVPNCloudFirewallIPorHost "95.211.35.162"
:global OpenVPNCloudUsername "CustomerName-City-Office"
:global OpenVPNCloudPassword "passwordddddd"
:global OpenVPNLocalIP "10.200.110.39"

# only Cloud Server Side variables
########***************** Masood
######  we should change format to 0000 
:global CustomerAdresList "0000-CustomerName"
#
:global CustomerOfficeSubnetComment "CustomerName Office Subnet"
:global CustomerInterfaceList "CustomerName"
:global CustomerFirewallRuleComment "CustomerName to CustomerName"
:global OpenVPNServerInterfaceName "OpenVPN_CustomerName-City-Office"

# not needef for non RDP Cloud customers
#:global CustomerCloudSubnet "10.0.99.0/24"
#:global CustomerCloudSubnetComment "CustomerName Cloud Subnet"
#:global ClientVLanInterfaceName "VLan-0099-CustomerName-Cloud"
#:global ClientVLanID "99"


# Create vlan for customer subnet (cloud vlan interface ) -- This is not needed for Voip only customers
## /interface vlan add interface=ether1-Trunk loop-protect=on name=$ClientVLanInterfaceName vlan-id=$ClientVLanID

# interface list ( Customer Cloud vlan interface in the interface list) -- This is not needed for Voip only customers
#/interface list add name=$CustomerInterfaceList
#/interface list set Customers include=$CustomerInterfaceList
# interface list append
/interface list add name=$CustomerInterfaceList
/interface/list/set Custom include=([get [find where name=Customers] include], $CustomerInterfaceList)


# Create openvpn 
/ppp secret
add name=$OpenVPNCloudUsername password=$OpenVPNCloudPassword profile=$OpenVPNProfileName remote-address=$OpenVPNLocalIP routes=$CustomerOfficeBigSubnet service=ovpn


# create openvpn interface -- Neded for remote management
/interface ovpn-server add name=$OpenVPNServerInterfaceName user=$OpenVPNCloudUsername
# add openvpn interface to customer list   
/interface list member add interface=$OpenVPNServerInterfaceName list=$CustomerInterfaceList

# add customer interface to customer interface list (Cloud Interface) -- This is not needed for Voip only customers
#/interface list member add interface=$ClientVLanInterfaceName list=$CustomerInterfaceList

# ip firewall
# add vpn interface ip to customer
/ip firewall address-list add address=$OpenVPNLocalIP list=$CustomerAdresList
# add big Office subnet
/ip firewall address-list add address=$CustomerOfficeBigSubnet list=$CustomerAdresList
# add customer cloud subnet to internet access list (Cloud ) -- This is not needed for Voip only customers
#/ip firewall address-list add address=$CustomerCloudSubnet comment=$CustomerCloudSubnetComment list=CloudPC_Internet


# add customer office Subnet to addresslist of customer
/ip firewall address-list add address=$OpenVPNOfficeSubnet comment=$CustomerOfficeSubnetComment list=$CustomerAdresList

# firewall rule 
/ip firewall filter add action=accept chain=forward comment=$CustomerFirewallRuleComment connection-state=new dst-address-list=$CustomerAdresList in-interface-list=$CustomerInterfaceList out-interface-list=$CustomerInterfaceList src-address-list=$CustomerAdresList place-before=10
