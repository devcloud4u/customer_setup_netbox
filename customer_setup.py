from extras.scripts import Script, StringVar, IntegerVar
from dcim.models import Site
from ipam.models import VLAN, Prefix
from tenancy.models import Tenant
from django.template.defaultfilters import slugify
from netaddr import IPNetwork


def increment_last_octet(ip_base, increment):
    parts = ip_base.split('.')
    last_octet = int(parts[-1]) + increment
    if last_octet > 246:
        raise ValueError(f"Specified subnet value {last_octet}, exceeds the maximum IP subnet limit (246). Please enter another subnet base.")
    new_base = '.'.join(parts[:-1] + [str(last_octet)])
    return new_base


def format_vlan_id(vlan_id):
    vlan_number = int(vlan_id)
    if vlan_number > 254:
        raise ValueError("VLAN can be a maximum of 254. Please enter a VLAN less than 254.")
    return vlan_id.zfill(4)


def align_to_subnet(ip_base, mask):
    network = IPNetwork(f"{ip_base}/{mask}")
    return str(network.network)


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
            tenant, created = Tenant.objects.get_or_create(name=data['customer_full_name'])
            self.log_info(f"Tenant {'created' if created else 'retrieved'}: {tenant.name}")

            office_site_name = f"{data['customer_short_name']} {data['customer_office_place']}"
            office_site_slug = slugify(office_site_name)
            office_site, created = Site.objects.get_or_create(name=office_site_name, slug=office_site_slug, tenant=tenant)
            self.log_info(f"Office site {'created' if created else 'retrieved'}: {office_site.name}")

            cloud_site_name = f"{data['customer_short_name']} Cloud"
            cloud_site_slug = slugify(cloud_site_name)
            cloud_site, created = Site.objects.get_or_create(name=cloud_site_name, slug=cloud_site_slug, tenant=tenant)
            self.log_info(f"Cloud site {'created' if created else 'retrieved'}: {cloud_site.name}")

            aligned_office_prefix_base = align_to_subnet(data['customer_21_subnet'], 21)
            office_prefix_str = f"{aligned_office_prefix_base}/21"
            office_prefix, created = Prefix.objects.get_or_create(prefix=office_prefix_str, site=office_site)
            self.log_info(f"/21 prefix for office site {'created' if created else 'retrieved'}: {office_prefix.prefix}")

            cloud_vlan_id = format_vlan_id(data['customer_cloud_vlanid'])
            cloud_vlan, created = VLAN.objects.get_or_create(vid=int(cloud_vlan_id), name=f"{data['customer_short_name']} Cloud", site=cloud_site)
            self.log_info(f"Cloud VLAN {'created' if created else 'retrieved'}: {cloud_vlan.name}")

            cloud_prefix_str = f"10.0.{cloud_vlan_id}.0/24"
            cloud_prefix, created = Prefix.objects.get_or_create(prefix=cloud_prefix_str, site=cloud_site, vlan=cloud_vlan)
            self.log_info(f"Cloud prefix {'created' if created else 'retrieved'}: {cloud_prefix.prefix}")

            base_ip = aligned_office_prefix_base
            subnet_addresses = [increment_last_octet(base_ip, i) for i in range(5)]

            vlans = [
                (20, "Office", subnet_addresses[1]),
                (30, "VoIP", subnet_addresses[2]),
                (40, "Security", subnet_addresses[3]),
                (90, "Guest", subnet_addresses[4])
            ]

            for vid, name, subnet in vlans:
                vlan, created = VLAN.objects.get_or_create(vid=vid, name=name, site=office_site)
                self.log_info(f"{name} VLAN {'created' if created else 'retrieved'}: {vlan.name}")

                prefix_str = f"{subnet}.0/24"
                prefix, created = Prefix.objects.get_or_create(prefix=prefix_str, site=office_site, vlan=vlan)
                self.log_info(f"{name} prefix {'created' if created else 'retrieved'}: {prefix.prefix}")

            infra_prefix_str = f"{subnet_addresses[0]}.0/24"
            infra_prefix, created = Prefix.objects.get_or_create(prefix=infra_prefix_str, site=office_site)
            self.log_info(f"Infra prefix {'created' if created else 'retrieved'}: {infra_prefix.prefix}")

            self.log_success("Customer setup script completed successfully")

        except ValueError as e:
            self.log_failure(str(e))


script = CustomerSetupScript
