# Search tenant
# rest same as new

import random
from extras.scripts import Script, StringVar, IntegerVar, ObjectVar
from dcim.models import Site
from ipam.models import VLAN, Prefix
from ipam.choices import PrefixStatusChoices
from tenancy.models import Tenant, TenantGroup
from extras.models import JournalEntry
from django.template.defaultfilters import slugify
from netaddr import IPNetwork, IPAddress


class S0011_Exist_Customer_New_Office_Mikrotik(Script):
    class Meta:
        name = "Custom Tenant Script"
        description = "Script with custom fields for tenant selection and additional customer information"

    tenant = ObjectVar(
        model=Tenant,
        label="Select Tenant",
        required=True
    )

    customer_short_name = StringVar(
        description="Customer short name",
        label="Customer Short Name",
        required=True
    )

    customer_cloud_vlanid = StringVar(
        description="Customer cloud VLAN ID",
        label="Customer Cloud VLAN ID",
        required=True
    )

    customer_21_subnet = StringVar(
        description="Customer 21 subnet",
        label="Customer 21 Subnet",
        required=True
    )

    local_vpn_ip = StringVar(
        description="Local VPN IP",
        label="Local VPN IP",
        required=True
    )

    def run(self, data, commit):
        tenant = data['tenant']
        customer_short_name = data['customer_short_name']
        customer_cloud_vlanid = data['customer_cloud_vlanid']
        customer_21_subnet = data['customer_21_subnet']
        local_vpn_ip = data['local_vpn_ip']

        self.log_info(f"Tenant: {tenant.name}")
        self.log_info(f"Customer Short Name: {customer_short_name}")
        self.log_info(f"Customer Cloud VLAN ID: {customer_cloud_vlanid}")
        self.log_info(f"Customer 21 Subnet: {customer_21_subnet}")
        self.log_info(f"Local VPN IP: {local_vpn_ip}")

        # Placeholder for additional logic or database updates
        self.log_success("Script completed successfully.")


script = S0011_Exist_Customer_New_Office_Mikrotik