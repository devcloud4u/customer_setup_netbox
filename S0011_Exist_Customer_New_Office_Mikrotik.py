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
        name = "S0011 Exist Customer New Office Mikrotik"
        description = "Script with custom fields for tenant selection and additional customer information"

    tenant = ObjectVar(
        model=Tenant,
        label="Select Tenant",
        required=True
    )

    site = ObjectVar(
        model=Site,
        label="Select Site",
        required=True,
        query_params={
            'tenant_id': '$tenant'
        }
    )

    customer_short_name = StringVar(
        description="Customer short name",
        label="Customer Short Name",
        required=True
    )

    customer_office_place = StringVar(
        description="Customer Office Place",
        label="Customer Office Place",
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

    def run(self, data, commit):
        try:
            self.log_info(f"Customer /21 Subnet: {data['customer_21_subnet']}")
            validated_subnet_base = self.validate_and_format_subnet_base(data['customer_21_subnet'])
            self.log_info(f"Validated Subnet Base: {validated_subnet_base}")

            tenant_group, created = TenantGroup.objects.get_or_create(name='Customers')
            tenant = data['tenant']
            self.log_info(f"Tenant 'retrieved': {tenant.name}")

            office_site_name = f"{data['customer_short_name']} {data['customer_office_place']}"
            office_site_slug = slugify(office_site_name)
            office_site, created = Site.objects.get_or_create(
                name=office_site_name,
                slug=office_site_slug,
                tenant=tenant,
                tenant_group=tenant_group,
            )
            self.log_info(f"Office site {'created' if created else 'retrieved'}: {office_site.name}")

            cloud_site_name = f"{data['customer_short_name']} Cloud"
            cloud_site_slug = slugify(cloud_site_name)
            cloud_site, created = Site.objects.get_or_create(
                name=cloud_site_name,
                slug=cloud_site_slug,
                tenant=tenant,
                tenant_group=tenant_group,
            )
            self.log_info(f"Cloud site {'created' if created else 'retrieved'}: {cloud_site.name}")

        except ValueError as e:
            self.log_failure(str(e))

        self.log_success("Script completed successfully.")


script = S0011_Exist_Customer_New_Office_Mikrotik