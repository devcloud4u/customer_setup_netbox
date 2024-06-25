# Search tenant
# rest same as new

import random
import netaddr
from extras.scripts import Script, StringVar, IntegerVar, ObjectVar, ChoiceVar
from dcim.models import Site
from ipam.models import VLAN, Prefix
from ipam.choices import PrefixStatusChoices
from tenancy.models import Tenant, TenantGroup
from extras.models import JournalEntry
from django.template.defaultfilters import slugify
from netaddr import IPNetwork, IPAddress
from extras.models import Tag


def generate_password(length=20):
    letters = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ"
    digits = "123456789"
    special_characters = ".-"
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")
    password = [
        random.choice(letters),
        random.choice(digits),
        random.choice(special_characters),
        random.choice(letters + digits + special_characters)
    ]
    remaining_length = length - 4
    all_characters = letters + digits + special_characters
    password += random.choices(all_characters, k=remaining_length)
    random.shuffle(password)
    return ''.join(password)


class S0011_Exist_Customer_New_Office_Mikrotik(Script):
    class Meta:
        name = "S0011 Exist Customer New Office Mikrotik"
        description = "Script with custom fields for tenant selection and additional customer information"

    tenant = ObjectVar(
        model=Tenant,
        label="Select Customer Tenant",
        description="New Office Site will be created below this Tenant",
        required=True
    )

    site = ObjectVar(
        model=Site,
        label="Select Customer Cloud Site",
        description="Cloud Mikrotik Config will be pushed on this site",
        required=True,
        query_params={
            'tenant_id': '$tenant'
        }
    )

    customer_office_place = StringVar(
        description="Customer Office Place or Street",
        label="Customer Office Place",
        required=True
    )

    customer_21_subnet = ObjectVar(
        model=Prefix,
        label="Customer 21 Subnet",
        required=True,
        query_params={
            'tag': 'active-customer-office-subnet'
        }
    )

    local_vpn_ip = StringVar(
        description="Local VPN IP",
        label="Local VPN IP",
        required=True
    )

    customer_cloud_firewall_interface_list_name = StringVar(
        description="Pls Check on Cloud Mikrotik 'Interfaces' --> 'Interface List' and find customer name",
        label="Customer Cloud Firewall Interface List name",
        required=True
    )

    customer_address_list_name_in_cloud_mikrotik = StringVar(
        description="Pls check on Cloud Mikrotik 'IP' --> 'Firewall' --> 'Address List' and find customer address list name like 0078-Cova",
        label="Customer Address List Name in Cloud Mikrotik",
        required=True
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.customer_21_subnet.query_params = self.prepare()

    def prepare(self):
        # Get the tag and find all prefixes tagged with it
        tag = Tag.objects.get(slug='active-customer-office-subnet')
        tagged_prefixes = Prefix.objects.filter(tags__in=[tag])
        available_subnets = []

        # For each tagged prefix, find available /21 subnets within it
        for tagged_prefix in tagged_prefixes:
            prefix_set = netaddr.IPSet([tagged_prefix.prefix])
            child_prefixes_set = netaddr.IPSet([child.prefix for child in tagged_prefix.get_child_prefixes()])
            available_prefixes = prefix_set - child_prefixes_set

            for subnet in available_prefixes.iter_cidrs():
                if subnet.prefixlen == 21:
                    available_subnets.append(str(subnet))

        # Set the query_params for customer_21_subnet
        return {
            'prefix__in': available_subnets
        }

    @staticmethod
    def validate_and_format_subnet_base(ip_base):
        # Strip the subnet mask if present
        if '/' in ip_base:
            ip_base = ip_base.split('/')[0]

        parts = ip_base.split('.')
        if len(parts) < 4:
            parts += ['0'] * (4 - len(parts))
        if len(parts) != 4:
            raise ValueError("Invalid subnet base. Please provide a base in the format X.X.X.0")
        if int(parts[-1]) != 0:
            raise ValueError("The last octet of the subnet base should be 0 (e.g., '10.201.16.0')")
        return '.'.join(parts)

    @staticmethod
    def align_to_subnet(ip_base, mask):
        network = IPNetwork(f"{ip_base}/{mask}")
        return str(network.network)

    @staticmethod
    def format_vlan_id(vlan_id):
        vlan_number = int(vlan_id)
        if vlan_number > 254:
            raise ValueError("VLAN can be a maximum of 254. Please enter a VLAN less than 254.")
        return str(vlan_number).zfill(4)

    @staticmethod
    def increment_subnet(ip_base, increment, subnet_mask):
        network = IPNetwork(f"{ip_base}/{subnet_mask}")
        new_network = network.next(increment)
        return str(new_network.network)

    @staticmethod
    def increment_last_octet(ip_base, count):
        ip = IPAddress(ip_base)
        return str(ip + count)

    def run(self, data, commit):
        try:
            cloud_site = data['site']
            vlan = VLAN.objects.filter(site=cloud_site).first()
            cloud_vlan_id = vlan.vid
            cloud_vlan_name = self.format_vlan_id(cloud_vlan_id)
            customer_short_name = cloud_site.name.split(' ')[0]
            self.log_info(f"Customer /21 Subnet: {data['customer_21_subnet']}")
            validated_subnet_base = self.validate_and_format_subnet_base(data['customer_21_subnet'])
            self.log_info(f"Validated Subnet Base: {validated_subnet_base}")

            tenant = data['tenant']
            self.log_info(f"Tenant 'retrieved': {tenant.name}")

            office_site_name = f"{customer_short_name} {data['customer_office_place']}"
            office_site_slug = slugify(office_site_name)
            office_site, created = Site.objects.get_or_create(
                name=office_site_name,
                slug=office_site_slug,
                tenant=tenant,
            )

            self.log_info(f"Office site {'created' if created else 'retrieved'}: {office_site.name}")

            aligned_office_prefix_base = self.align_to_subnet(validated_subnet_base, 21)
            office_prefix_str = f"{aligned_office_prefix_base}/21"
            self.log_info(f"Office Prefix: {office_prefix_str}")
            office_prefix, created = Prefix.objects.get_or_create(
                prefix=office_prefix_str,
                site=office_site,
                tenant=tenant,
                status=PrefixStatusChoices.STATUS_CONTAINER,
                is_pool=True
            )
            self.log_info(f"/21 prefix for office site {'created' if created else 'retrieved'}: {office_prefix.prefix}")

            base_ip = aligned_office_prefix_base
            subnet_addresses = [self.increment_subnet(base_ip, i, 24) for i in range(5)]
            self.log_info(f"Subnet Addresses: {subnet_addresses}")

            vlans = [
                (20, "Office", subnet_addresses[1]),
                (30, "VoIP", subnet_addresses[2]),
                (40, "Security", subnet_addresses[3]),
                (90, "Guest", subnet_addresses[4])
            ]

            for vid, name, subnet in vlans:
                vlan, created = VLAN.objects.get_or_create(vid=vid, name=name, site=office_site, tenant=tenant)
                self.log_info(f"{name} VLAN {'created' if created else 'retrieved'}: {vlan.name}")

                prefix_str = f"{subnet}/24"
                self.log_info(f"{name} Prefix: {prefix_str}")
                prefix, created = Prefix.objects.get_or_create(
                    prefix=prefix_str,
                    site=office_site,
                    vlan=vlan,
                    tenant=tenant
                )
                self.log_info(f"{name} prefix {'created' if created else 'retrieved'}: {prefix.prefix}")

            infra_prefix_str = f"{subnet_addresses[0]}/24"
            self.log_info(f"Infra Prefix: {infra_prefix_str}")
            infra_prefix, created = Prefix.objects.get_or_create(
                prefix=infra_prefix_str,
                site=office_site,
                tenant=tenant
            )
            self.log_info(f"Infra prefix {'created' if created else 'retrieved'}: {infra_prefix.prefix}")

            password = generate_password(20)
            openvpn_password = generate_password(20)

            save_password_template = f"""
passbolt please save this
======
uri: {data['local_vpn_ip']}:35300
username: admin
password: {password}

Office mikrotik code to copy paste
======

            """
            cloud_template = f'''
# This is for Mikrotik Cloud to add new OpenVPN to Customer Office mikrotik  
# For Office: "{customer_short_name}-{data['customer_office_place']}-Office"

# Info
#################
# $CustomerInterfaceList = ask from user
# name: Customer Cloud Firewall  Interface List name:
# tip: Pls Check on Cloud Mikrotik "Interfaces" --> "Interface List" and find customer name

# $CustomerAdresList = ask from user
# name: Customer Address List Name in Cloud Mikrotik: 
# tip: Pls chek on Cloud Mikrotik "IP" --> "Firewall" --> "Address List" and find customer adres list name like 0078-Cova

# $customer_office_place  get from user
# name: Customer Office Name
# tip: Customer Office Place or Street 

# $customer_short_name Get fro Cloud Office Site 
# $OpenVPNCloudUsername generated on Office Site 
# en info
#########

# Generate for Journal in Customer Cloud Side
###########
# only Cloud Server Side variables
:global OpenVPNServerInterfaceName "OpenVPN_{customer_short_name}-{data['customer_office_place']}-Office"
:global CustomerFirewallRuleComment "{customer_short_name} to {customer_short_name}"
:global CustomerInterfaceList "{data['customer_cloud_firewall_interface_list_name']}"
:global CustomerAdresList "{data['customer_address_list_name_in_cloud_mikrotik']}"
:global CustomerOfficeBigSubnet "{base_ip}/21"
:global OpenVPNLocalIP "{data['local_vpn_ip']}"
:global OpenVPNCloudUsername "{customer_short_name}-{data['customer_office_place']}-Office"
:global OpenVPNCloudPassword "{openvpn_password}"

# static variables
:global OpenVPNProfileName "OpenVPN_Profile"


# create openvpn interface
/interface ovpn-server add name=$OpenVPNServerInterfaceName user=$OpenVPNCloudUsername
# add openvpn interface to customer list
/interface list member add interface=$OpenVPNServerInterfaceName list=$CustomerInterfaceList

# ip firewall
# add vpn interface ip to customer
/ip firewall address-list add address=$OpenVPNLocalIP list=$CustomerAdresList
# add big Office subnet
/ip firewall address-list add address=$CustomerOfficeBigSubnet list=$CustomerAdresList


# Create openvpn 
/ppp secret
add name=$OpenVPNCloudUsername password=$OpenVPNCloudPassword profile=$OpenVPNProfileName remote-address=$OpenVPNLocalIP routes=$CustomerOfficeBigSubnet service=ovpn

# firewall rule 
/ip firewall filter add action=accept chain=forward comment=$CustomerFirewallRuleComment connection-state=new dst-address-list=$CustomerAdresList in-interface-list=$CustomerInterfaceList out-interface-list=$CustomerInterfaceList src-address-list=$CustomerAdresList place-before=10
            '''
            # Create the script template with generated variables and settings
            script_template = f"""

:global NameDevice "{customer_short_name}-{data['customer_office_place']}-Office"
:global AdminPassword "{password}"
:global DnsServers "8.8.8.8,8.8.4.4,1.1.1.1"

:global CustomerOfficeBigSubnet "{base_ip}/21"

:global InfraGWIp "{self.increment_last_octet(subnet_addresses[0], 1)}"
:global InfraIp "{self.increment_last_octet(subnet_addresses[0], 1)}/24"
:global InfraIpNetwork "{self.increment_last_octet(subnet_addresses[0], 0)}"
:global InfraIpSubnet "{self.increment_last_octet(subnet_addresses[0], 0)}/24"
:global PoolInfra "{self.increment_last_octet(subnet_addresses[0], 99)}-{self.increment_last_octet(subnet_addresses[0], 253)}"

:global OfficeGWIp "{self.increment_last_octet(subnet_addresses[1], 1)}"
:global OfficeIp "{self.increment_last_octet(subnet_addresses[1], 1)}/24"
:global OfficeIpNetwork "{self.increment_last_octet(subnet_addresses[1], 0)}"
:global OfficeIpSubnet "{self.increment_last_octet(subnet_addresses[1], 0)}/24"
:global PoolOffice "{self.increment_last_octet(subnet_addresses[1], 99)}-{self.increment_last_octet(subnet_addresses[1], 253)}"

:global VoipGWIp "{self.increment_last_octet(subnet_addresses[2], 1)}"
:global VoipIp "{self.increment_last_octet(subnet_addresses[2], 1)}/24"
:global VoipIpNetwork "{self.increment_last_octet(subnet_addresses[2], 0)}"
:global VoipIpSubnet "{self.increment_last_octet(subnet_addresses[2], 0)}/24"
:global PoolVoip "{self.increment_last_octet(subnet_addresses[2], 99)}-{self.increment_last_octet(subnet_addresses[2], 253)}"

:global SecurityGWIp "{self.increment_last_octet(subnet_addresses[3], 1)}"
:global SecurityIp "{self.increment_last_octet(subnet_addresses[3], 1)}/24"
:global SecurityIpNetwork "{self.increment_last_octet(subnet_addresses[3], 0)}"
:global SecurityIpSubnet "{self.increment_last_octet(subnet_addresses[3], 0)}/24"
:global PoolSecurity "{self.increment_last_octet(subnet_addresses[3], 99)}-{self.increment_last_octet(subnet_addresses[3], 253)}"

:global GuestGWIp "{self.increment_last_octet(subnet_addresses[4], 1)}"
:global GuestIp "{self.increment_last_octet(subnet_addresses[4], 1)}/24"
:global GuestIpNetwork "{self.increment_last_octet(subnet_addresses[4], 0)}"
:global GuestIpSubnet "{self.increment_last_octet(subnet_addresses[4], 0)}/24"
:global PoolGuest "{self.increment_last_octet(subnet_addresses[4], 99)}-{self.increment_last_octet(subnet_addresses[4], 253)}"

# static variables
:global OpenVPNProfileName "OpenVPN_Profile"
:global OpenVPNClientName "OpenVPN_Cloud"
:global ServiceSubnet "10.200.110.0/24"
:global OpenVPNServerInterfaceIP "10.200.110.1"

# Cloud Server and Client Office side variables
:global OpenVPNCloudFirewallIPorHost "95.211.35.162"
:global OpenVPNCloudUsername "{customer_short_name}-{data['customer_office_place']}-Office"
:global OpenVPNCloudPassword {openvpn_password}
:global OpenVPNLocalIP "{data['local_vpn_ip']}"

# only Cloud Server Side variables
:global CustomerAdresList "{cloud_vlan_name}-{customer_short_name}"
:global CustomerCloudSubnet "10.0.{cloud_vlan_id}.0/24"
:global CustomerCloudSubnetComment "{customer_short_name} Cloud Subnet"
:global CustomerInterfaceList "{customer_short_name}"
:global CustomerFirewallRuleComment "{customer_short_name} to {customer_short_name}"
:global OpenVPNServerInterfaceName "OpenVPN_{customer_short_name}-{data['customer_office_place']}-Office"
:global ClientVLanInterfaceName "VLan-{cloud_vlan_name}-{customer_short_name}-Cloud"
:global ClientVLanID "{cloud_vlan_id}"


### reset to factory
#/system reset-configuration no-defaults=yes skip-backup=yes

# !!!!! do not use ether1 for programming use last port like port 4 or 5

### Reset only mac addresses
#/interface ethernet reset-mac-address

### template without voipmax
### System Name 
/system identity set name=$NameDevice

### Set Password
/user set [find name=admin] password=$AdminPassword

### Interface Names
/interface ethernet
set [ find default-name=ether1 ] name=ether1_Trunk_Switch
set [ find default-name=ether2 ] name=ether2_WAN1
set [ find default-name=ether3 ] name=ether3_WAN2
set [ find default-name=ether4 ] name=ether4
set [ find default-name=ether5 ] name=ether5

### OpenVPN Clients
/interface ovpn-client
# Add OpenVPN client for Ortimo VPN 
add connect-to=$OpenVPNCloudFirewallIPorHost name=$OpenVPNClientName password=$OpenVPNCloudPassword user=$OpenVPNCloudUsername

### Interface Bridge with VLAN Filtering
/interface bridge
add name=Bridge_Trunk vlan-filtering=yes

### VLAN Interfaces
# Creating VLAN Interfaces on the Bridge for various network segments
/interface vlan
add interface=Bridge_Trunk vlan-id=20 name="VLAN_0020_Office"
add interface=Bridge_Trunk vlan-id=30 name="VLAN_0030_Voip"
add interface=Bridge_Trunk vlan-id=40 name="VLAN_0040_Security"
add interface=Bridge_Trunk vlan-id=90 name="VLAN_0090_Guest"

### Bridge VLAN Configuration
# VLAN 10 untagged on ether1_Trunk_Switch, other VLANs tagged
/interface bridge vlan
add bridge=Bridge_Trunk tagged=ether1_Trunk_Switch,Bridge_Trunk vlan-ids=20
add bridge=Bridge_Trunk tagged=ether1_Trunk_Switch,Bridge_Trunk vlan-ids=30
add bridge=Bridge_Trunk tagged=ether1_Trunk_Switch,Bridge_Trunk vlan-ids=40
add bridge=Bridge_Trunk tagged=ether1_Trunk_Switch,Bridge_Trunk vlan-ids=90

### Bridge Ports
/interface bridge port
add bridge=Bridge_Trunk interface=ether1_Trunk_Switch

### Interface Lists
/interface list
add name=Infra
add name=Office
add name=VoIP
add name=Security
add name=Guest
add name=WAN
add name=Cloud

# Add LAN interface including other interface lists 
add include=Infra,Office,Security,VoIP,Guest name=LAN

#### IP Pools
/ip pool
add ranges=$PoolInfra name=Pool_Infra
add ranges=$PoolOffice name=Pool_Office
add ranges=$PoolVoip name=Pool_VoIP
add ranges=$PoolSecurity name=Pool_Security
add ranges=$PoolGuest name=Pool_Guest

### IP Addresses
/ip address
# Untagged VLAN 1 used as Infra its bridge
add address=$InfraIp interface=Bridge_Trunk network=$InfraIpNetwork
add address=$OfficeIp interface=VLAN_0020_Office network=$OfficeIpNetwork
add address=$VoipIp interface=VLAN_0030_Voip network=$VoipIpNetwork
add address=$SecurityIp interface=VLAN_0040_Security network=$SecurityIpNetwork
add address=$GuestIp interface=VLAN_0090_Guest network=$GuestIpNetwork

### DHCP Servers
/ip dhcp-server
add address-pool=Pool_Infra interface=Bridge_Trunk lease-time=1w name=DHCP_Infra
add address-pool=Pool_Office interface=VLAN_0020_Office lease-time=2d name=DHCP_Office
add address-pool=Pool_VoIP interface=VLAN_0030_Voip lease-time=1w name=DHCP_VoIP
add address-pool=Pool_Security interface=VLAN_0040_Security lease-time=1w name=DHCP_Security
add address-pool=Pool_Guest interface=VLAN_0090_Guest lease-time=1h name=DHCP_Guest

### interface member lists	
/interface list member
add interface=ether1_Trunk_Switch list=Infra
add interface=Bridge_Trunk list=Infra
add interface=$OpenVPNClientName list=Cloud
add interface=VLAN_0020_Office list=Office
add interface=VLAN_0030_Voip list=VoIP
add interface=VLAN_0040_Security list=Security
add interface=VLAN_0090_Guest list=Guest
#mybe not needed
add interface=ether2_WAN1 list=WAN
#mybe not needed
add interface=ether3_WAN2 list=WAN

### dhcp client 
/ip dhcp-client
# main internet
add add-default-route=yes default-route-distance=1 interface=ether2_WAN1
# backup internet
add add-default-route=yes default-route-distance=5 interface=ether3_WAN2

### DHCP Servers Network Configuration
/ip dhcp-server network
add address=$InfraIpSubnet dns-server=$InfraGWIp gateway=$InfraGWIp
add address=$OfficeIpSubnet dns-server=$OfficeGWIp gateway=$OfficeGWIp
add address=$VoipIpSubnet dns-server=$VoipGWIp gateway=$VoipGWIp
add address=$SecurityIpSubnet dns-server=$SecurityGWIp gateway=$SecurityGWIp
add address=$GuestIpSubnet dns-server=$GuestGWIp gateway=$GuestGWIp

### DNS Static Reservations
/ip dns
set allow-remote-requests=yes
/ip dns static

### routes
/ip route add disabled=no dst-address=$CustomerCloudSubnet gateway=$OpenVPNServerInterfaceIP routing-table=main suppress-hw-offload=no

### dns server settings
/ip dns set servers=$DnsServers
/ip dns set cache-max-ttl=0s
/ip dns set allow-remote-requests=yes

/ip firewall address-list
add list=AdminAccess address=$ServiceSubnet

### IP firewall setup
/ip firewall filter
# Allow traffic from OpenVPN_Cloud VPN to LAN
add action=accept chain=forward connection-state=new,established,related in-interface=OpenVPN_Cloud out-interface-list=LAN comment="Allow from Ortimo to LAN"
# FastTrack established and related connections for high-throughput
add action=fasttrack-connection chain=forward connection-state=established,related hw-offload=yes comment="FastTrack for established and related connections"
# Accept established and related connections
add action=accept chain=forward connection-state=established,related comment="Accept established and related connections"
# Accept established and related connections on input chain
add action=accept chain=input connection-state=established,related comment="Accept established and related connections on input"
# Allow Winbox access
add action=accept chain=input connection-state=new dst-port=35300 protocol=tcp comment="Allow Winbox access"
/ip firewall filter
# Allow SSH access from AdminAccess list
add action=accept chain=input connection-state=new dst-port=2220 protocol=tcp src-address-list=AdminAccess comment="Allow SSH from AdminAccess list"
# Allow WebFig access from AdminAccess list
add action=accept chain=input connection-state=new dst-port=8181 protocol=tcp src-address-list=AdminAccess comment="Allow WebFig from AdminAccess list"
# Allow LAN to access the internet
add action=accept chain=forward in-interface-list=LAN out-interface-list=WAN comment="Allow internet access from LAN"
# Allow Cloud network to access LAN
add action=accept chain=forward in-interface-list=Cloud out-interface-list=LAN comment="Allow access from Cloud to LAN"
# Inter-VLAN routing rules
add action=accept chain=forward connection-state=new in-interface-list=Guest out-interface-list=Guest comment="Allow Guest to Guest communication"
add action=accept chain=forward connection-state=new in-interface-list=Infra out-interface-list=Infra comment="Allow Infra to Infra communication"
add action=accept chain=forward connection-state=new in-interface-list=Office out-interface-list=Office comment="Allow Office to Office communication"
add action=accept chain=forward connection-state=new in-interface-list=Security out-interface-list=Security comment="Allow Security to Security communication"
add action=accept chain=forward connection-state=new in-interface-list=VoIP out-interface-list=VoIP comment="Allow VoIP to VoIP communication"
add action=accept chain=forward in-interface-list=LAN out-interface-list=Cloud comment="Allow From Lan to Cloud communication"
# Allow ICMP on input chain
add action=accept chain=input protocol=icmp comment="Allow ICMP ping"
# Drop all other incoming connections on WAN interface
add action=drop chain=input in-interface-list=WAN comment="Drop all other incoming connections on WAN"
# Drop invalid and non-DSTNAT forwarded traffic from WAN
add action=drop chain=forward connection-nat-state=!dstnat out-interface-list=!WAN comment="Drop invalid and non-DSTNAT forward from WAN"
add action=drop chain=forward connection-nat-state=!dstnat connection-state=new in-interface-list=WAN comment="Drop new non-DSTNAT forward from WAN"
add action=drop chain=forward connection-state=invalid in-interface-list=WAN comment="Drop invalid forward from WAN"

### Firewall NAT
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN comment="Masquerade for outbound traffic from LAN to WAN"

### ip services  disable
/ip service
set telnet disabled=yes
set ftp disabled=yes
set api disabled=yes
set api-ssl disabled=yes

### ip services custom 
/ip service
set winbox port=35300
set www port=8181
set ssh port=2220

### system settings 
/system clock
set time-zone-name=Europe/Amsterdam

### time client 
/system ntp client
set enabled=yes
/system ntp client servers
add address=3.nl.pool.ntp.org

### sys note
/system note
set show-at-login=no

### sys loggig to memory remember
/system logging
/system/logging/action/set memory remember=yes

# add dhcp option to wificontrol (wificontrol unifi inform option)
/ip dhcp-server option add code=43 name=unifi-wificontrol value=0x010455115F33

# link this option to first dhcp server ! first dhcp server should be infra dhcp server
# find in ui -ip --> DHCP server --> Networks
/ip dhcp-server network set 0 dhcp-option=unifi-wificontrol
/ip dhcp-server network set 1 dhcp-option=unifi-wificontrol
/ip dhcp-server network set 2 dhcp-option=unifi-wificontrol
/ip dhcp-server network set 3 dhcp-option=unifi-wificontrol
/ip dhcp-server network set 4 dhcp-option=unifi-wificontrol
/ip dhcp-server network set 5 dhcp-option=unifi-wificontrol

#Extra Settings
/system note set show-at-login=no
/system logging action set memory remember=yes

#Securing Mikrotik
/ip ssh set strong-crypto=yes forwarding-enabled=both

# extra security 
/tool mac-server mac-winbox set allowed-interface-list=LAN
/tool mac-server ping set enabled=no
/ip neighbor discovery-settings set discover-interface-list=LAN
/tool bandwidth-server set enabled=no
/ip proxy set enabled=no
/ip socks set enabled=no
/ip upnp set enabled=no
/ip cloud set ddns-enabled=no update-time=no
/lcd set enabled=no

# mikrotik mode change + give options
/system/device-mode/update mode=enterprise scheduler=yes socks=yes fetch=yes pptp=yes l2tp=yes bandwidth-test=yes traffic-gen=yes sniffer=yes ipsec=yes romon=yes proxy=yes hotspot=yes smb=yes email=yes zerotier=yes container=yes
# power off on physically in 5 min
'''

cloud_site_template = '''
# Create vlan for customer subnet (Cloud vLan Interface)
/interface vlan add interface=ether1-Trunk loop-protect=on name=$ClientVLanInterfaceName vlan-id=$ClientVLanID

# interface list
/interface list add name=$CustomerInterfaceList
/interface list add include=$CustomerInterfaceList name=Customers

# create openvpn interface
/interface ovpn-server add name=$OpenVPNServerInterfaceName user=$OpenVPNCloudUsername
# add openvpn interface to customer list
/interface list member add interface=$OpenVPNServerInterfaceName list=$CustomerInterfaceList

# add customer interface to customer interface list
/interface list member add interface=$ClientVLanInterfaceName list=$CustomerInterfaceList

# ip firewall
# add vpn interface ip to customer
/ip firewall address-list add address=$OpenVPNLocalIP list=$CustomerAdresList
# add big Office subnet
/ip firewall address-list add address=$CustomerOfficeBigSubnet list=$CustomerAdresList
# add customer cloud subnet to internet access list
/ip firewall address-list add address=$CustomerCloudSubnet comment=$CustomerCloudSubnetComment list=CloudPC_Internet

# Create openvpn 
/ppp secret
add name=$OpenVPNCloudUsername password=$OpenVPNCloudPassword profile=$OpenVPNProfileName remote-address=$OpenVPNLocalIP routes=$CustomerOfficeBigSubnet service=ovpn

# firewall rule 
/ip firewall filter add action=accept chain=forward comment=$CustomerFirewallRuleComment connection-state=new dst-address-list=$CustomerAdresList in-interface-list=$CustomerInterfaceList out-interface-list=$CustomerInterfaceList src-address-list=$CustomerAdresList place-before=10
            """

            JournalEntry.objects.create(
                assigned_object=office_site,
                created_by=self.request.user,
                comments=f'```\n{save_password_template}\n{script_template}\n```'
            )

            JournalEntry.objects.create(
                assigned_object=cloud_site,
                created_by=self.request.user,
                comments=f'```\n{cloud_template}\n```'
            )

        except ValueError as e:
            self.log_failure(str(e))

        self.log_success("Script completed successfully.")


script = S0011_Exist_Customer_New_Office_Mikrotik
