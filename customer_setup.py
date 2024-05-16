# netbox/extras/scripts/customer_setup.py

from extras.scripts import Script, StringVar, IntegerVar
from dcim.models import Site
from ipam.models import VLAN, Prefix
from tenancy.models import Tenant
from django.template.defaultfilters import slugify
from netaddr import IPNetwork, IPAddress


def increment_subnet(ip_base, increment, subnet_mask):
    network = IPNetwork(f"{ip_base}/{subnet_mask}")
    new_network = network.next(increment)
    return str(new_network.network)


def format_vlan_id(vlan_id):
    vlan_number = int(vlan_id)
    if vlan_number > 254:
        raise ValueError("VLAN can be a maximum of 254. Please enter a VLAN less than 254.")
    return str(vlan_number).zfill(4)


def align_to_subnet(ip_base, mask):
    network = IPNetwork(f"{ip_base}/{mask}")
    return str(network.network)


def validate_and_format_subnet_base(ip_base):
    parts = ip_base.split('.')
    if len(parts) < 4:
        parts += ['0'] * (4 - len(parts))
    if len(parts) != 4:
        raise ValueError("Invalid subnet base. Please provide a base in the format X.X.X.0")
    if int(parts[-1]) != 0:
        raise ValueError("The last octet of the subnet base should be 0 (e.g., '10.201.16.0')")
    return '.'.join(parts)


class CustomerSetupScript(Script):
    class Meta:
        name = "Customer Setup Script"
        description = "Sets up tenant, sites, VLANs, and prefixes for a new customer"

    customer_full_name = StringVar(description="Customer Full Name (e.g., 'Ali Transport')")
    customer_short_name = StringVar(description="Customer Short Name (e.g., 'Ali')")
    customer_office_place = StringVar(description="Customer Office Place (e.g., 'Istanbul')")
    customer_cloud_vlanid = IntegerVar(description="Customer Cloud VLAN ID (e.g., '10')")
    customer_21_subnet = StringVar(description="Customer /21 Subnet Base (e.g., '10.201.16')")
    local_vpn_ip = StringVar(description="Local VPN IP (e.g., '10.200.110.38')")

    def run(self, data, commit):
        try:
            # Validate and format the subnet base
            validated_subnet_base = validate_and_format_subnet_base(data['customer_21_subnet'])

            # Create tenant
            tenant, created = Tenant.objects.get_or_create(name=data['customer_full_name'])
            self.log_info(f"Tenant {'created' if created else 'retrieved'}: {tenant.name}")

            # Create office site
            office_site_name = f"{data['customer_short_name']} {data['customer_office_place']}"
            office_site_slug = slugify(office_site_name)
            office_site, created = Site.objects.get_or_create(name=office_site_name, slug=office_site_slug,
                                                              tenant=tenant)
            self.log_info(f"Office site {'created' if created else 'retrieved'}: {office_site.name}")

            # Create cloud site
            cloud_site_name = f"{data['customer_short_name']} Cloud"
            cloud_site_slug = slugify(cloud_site_name)
            cloud_site, created = Site.objects.get_or_create(name=cloud_site_name, slug=cloud_site_slug, tenant=tenant)
            self.log_info(f"Cloud site {'created' if created else 'retrieved'}: {cloud_site.name}")

            # Align and create /21 prefix for office site
            aligned_office_prefix_base = align_to_subnet(validated_subnet_base, 21)
            office_prefix_str = f"{aligned_office_prefix_base}/21"
            office_prefix, created = Prefix.objects.get_or_create(prefix=office_prefix_str, site=office_site)
            self.log_info(f"/21 prefix for office site {'created' if created else 'retrieved'}: {office_prefix.prefix}")

            # Create VLAN and prefix for cloud site
            cloud_vlan_id = int(data['customer_cloud_vlanid'])  # Ensure it's an integer for IP address
            cloud_vlan_name = format_vlan_id(data['customer_cloud_vlanid'])  # Use zfilled for display
            cloud_vlan, created = VLAN.objects.get_or_create(vid=cloud_vlan_id,
                                                             name=f"{data['customer_short_name']} Cloud",
                                                             site=cloud_site)
            self.log_info(f"Cloud VLAN {'created' if created else 'retrieved'}: {cloud_vlan.name}")

            cloud_prefix_str = f"10.0.{cloud_vlan_id}.0/24"  # Use integer directly for IP address
            cloud_prefix, created = Prefix.objects.get_or_create(prefix=cloud_prefix_str, site=cloud_site,
                                                                 vlan=cloud_vlan)
            self.log_info(f"Cloud prefix {'created' if created else 'retrieved'}: {cloud_prefix.prefix}")

            # Create additional VLANs and prefixes for office site
            base_ip = aligned_office_prefix_base
            subnet_addresses = [increment_subnet(base_ip, i, 24) for i in range(5)]

            vlans = [
                (20, "Office", subnet_addresses[1]),
                (30, "VoIP", subnet_addresses[2]),
                (40, "Security", subnet_addresses[3]),
                (90, "Guest", subnet_addresses[4])
            ]

            for vid, name, subnet in vlans:
                vlan, created = VLAN.objects.get_or_create(vid=vid, name=name, site=office_site)
                self.log_info(f"{name} VLAN {'created' if created else 'retrieved'}: {vlan.name}")

                prefix_str = f"{subnet}/24"
                prefix, created = Prefix.objects.get_or_create(prefix=prefix_str, site=office_site, vlan=vlan)
                self.log_info(f"{name} prefix {'created' if created else 'retrieved'}: {prefix.prefix}")

            # Create /24 prefix for Infra IP
            infra_prefix_str = f"{subnet_addresses[0]}/24"
            infra_prefix, created = Prefix.objects.get_or_create(prefix=infra_prefix_str, site=office_site)
            self.log_info(f"Infra prefix {'created' if created else 'retrieved'}: {infra_prefix.prefix}")

            # Log completion
            self.log_success("Customer setup script completed successfully")

        except ValueError as e:
            self.log_failure(str(e))


script = CustomerSetupScript
