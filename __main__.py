import pulumi
import uuid
from pulumi_azure_native import resources, network, compute, storage, operationalinsights, insights, authorization
import pulumi_azure_native as azure_native
import pulumi_azuread as azuread


# Konfigurationseinstellungen laden
config = pulumi.Config()
azure_location = config.get("azure-native:location") or "uksouth"
email_gregoire = "wi22b060@technikum-wien.at"

# Ressourcengruppe erstellen
resource_group = azure_native.resources.ResourceGroup("A8ResourceGroup", resource_group_name="A8ResourceGroup")
user_gregoire = azuread.get_user(user_principal_name=email_gregoire)

def assign_reader_role(user_object_id, resource_group, role_name_suffix):
    reader_role_definition_id = (
        f"/subscriptions/6af93ac4-5014-406c-b711-f718798bb0ae/providers/Microsoft.Authorization/"
        "roleDefinitions/acdd72a7-3385-48ef-bd42-f606fba81ae7"
    )
    role_assignment_name = str(uuid.uuid4())
    role_assignment = authorization.RoleAssignment(
        f"readerRoleAssignment-{role_name_suffix}-{role_assignment_name}",
        scope=resource_group.id,
        role_assignment_name=role_assignment_name,
        principal_id=user_object_id,
        role_definition_id=reader_role_definition_id,
        principal_type="User",
    )
    return role_assignment.id

role_assignment_id_gregoire = assign_reader_role(user_gregoire.object_id, resource_group, "gregoire")


# Storage-Konto erstellen
storage_account = azure_native.storage.StorageAccount(
    "diagstorage",
    resource_group_name=resource_group.name,
    sku=azure_native.storage.SkuArgs(name="Standard_LRS"),
    kind="StorageV2",
    location=resource_group.location,
)
storage_account_uri = storage_account.primary_endpoints.apply(lambda endpoints: endpoints.blob)

# Log Analytics Workspace erstellen
log_analytics_workspace = operationalinsights.Workspace(
    "logAnalyticsWorkspace",
    resource_group_name=resource_group.name,
    location=azure_location,
    sku=operationalinsights.WorkspaceSkuArgs(name="PerGB2018"),
    retention_in_days=30
)

# Virtual Network mit Subnetz erstellen
virtual_network = azure_native.network.VirtualNetwork("vnet",
    resource_group_name=resource_group.name,
    virtual_network_name=resource_group.name.apply(lambda name: f"{name}-vnet"),
    address_space=azure_native.network.AddressSpaceArgs(
        address_prefixes=["10.0.0.0/16"]
    ))

subnet = azure_native.network.Subnet("subnet",
    resource_group_name=resource_group.name,
    virtual_network_name=virtual_network.name,
    subnet_name=resource_group.name.apply(lambda name: f"{name}-subnet"),
    address_prefix="10.0.1.0/24")

# Network Security Group erstellen
network_security_group = azure_native.network.NetworkSecurityGroup("nsg",
    resource_group_name=resource_group.name,
    network_security_group_name=resource_group.name.apply(lambda name: f"{name}-nsg"))

# Sicherheitsregel erstellen (Port 80 erlauben)
security_rule = azure_native.network.SecurityRule("allow80InboundRule",
    resource_group_name=resource_group.name,
    network_security_group_name=network_security_group.name,
    security_rule_name="Allow-80-Inbound",
    priority=110,
    direction="Inbound",
    access="Allow",
    protocol="Tcp",
    source_port_range="*",
    destination_port_range="80",
    source_address_prefix="*",
    destination_address_prefix="*")

# Öffentliche IP-Adresse für den Load Balancer erstellen
public_ip = azure_native.network.PublicIPAddress(
    "publicIP",
    resource_group_name=resource_group.name,
    public_ip_address_name="A8PublicIP",
    sku=azure_native.network.PublicIPAddressSkuArgs(name="Standard"),
    public_ip_allocation_method="Static",
    zones=["1", "2", "3"]
)

# Load Balancer erstellen
load_balancer = azure_native.network.LoadBalancer("loadBalancer",
    resource_group_name=resource_group.name,
    load_balancer_name="A8LoadBalancer",
    sku=azure_native.network.LoadBalancerSkuArgs(name="Standard"),
    frontend_ip_configurations=[azure_native.network.FrontendIPConfigurationArgs(
        name="myFrontEnd",
        public_ip_address=azure_native.network.PublicIPAddressArgs(
            id=public_ip.id
        )
    )],
    backend_address_pools=[azure_native.network.BackendAddressPoolArgs(name="myBackEndPool")],
    probes=[azure_native.network.ProbeArgs(
        name="httpProbe",
        protocol="Http",
        port=80,
        request_path="/",
        interval_in_seconds=15,
        number_of_probes=2
    )],
    load_balancing_rules=[azure_native.network.LoadBalancingRuleArgs(
        name="httpRule",
        frontend_ip_configuration=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/resourceGroups/A8ResourceGroup/providers/Microsoft.Network/loadBalancers/A8LoadBalancer/frontendIPConfigurations/myFrontEnd"
        ),
        backend_address_pool=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/resourceGroups/A8ResourceGroup/providers/Microsoft.Network/loadBalancers/A8LoadBalancer/backendAddressPools/myBackEndPool"
        ),
        probe=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/resourceGroups/A8ResourceGroup/providers/Microsoft.Network/loadBalancers/A8LoadBalancer/probes/httpProbe"
        ),
        protocol="Tcp",
        frontend_port=80,
        backend_port=80,
        enable_floating_ip=False,
        idle_timeout_in_minutes=4,
        load_distribution="Default"
    )])

# Netzwerk-Schnittstellen für VM1 und VM2 erstellen
nic1 = azure_native.network.NetworkInterface("nic1",
    resource_group_name=resource_group.name,
    network_interface_name=resource_group.name.apply(lambda name: f"{name}-nic1"),
    ip_configurations=[azure_native.network.NetworkInterfaceIPConfigurationArgs(
        name="ipconfig1",
        subnet=azure_native.network.SubResourceArgs(id=subnet.id),
        private_ip_allocation_method="Dynamic",
        load_balancer_backend_address_pools=[azure_native.network.SubResourceArgs(
            id=load_balancer.backend_address_pools[0].id
        )]
    )],
    network_security_group=azure_native.network.SubResourceArgs(id=network_security_group.id))

nic2 = azure_native.network.NetworkInterface("nic2",
    resource_group_name=resource_group.name,
    network_interface_name=resource_group.name.apply(lambda name: f"{name}-nic2"),
    ip_configurations=[azure_native.network.NetworkInterfaceIPConfigurationArgs(
        name="ipconfig1",
        subnet=azure_native.network.SubResourceArgs(id=subnet.id),
        private_ip_allocation_method="Dynamic",
        load_balancer_backend_address_pools=[azure_native.network.SubResourceArgs(
            id=load_balancer.backend_address_pools[0].id
        )]
    )],
    network_security_group=azure_native.network.SubResourceArgs(id=network_security_group.id))

# Managed Disks für die VMs erstellen
data_disk1 = azure_native.compute.Disk("dataDisk1",
    resource_group_name=resource_group.name,
    location=azure_location,
    disk_name="vm1-disk",
    sku=azure_native.compute.DiskSkuArgs(name="Standard_LRS"),
    disk_size_gb=32,
    creation_data=azure_native.compute.CreationDataArgs(create_option="Empty"))

data_disk2 = azure_native.compute.Disk("dataDisk2",
    resource_group_name=resource_group.name,
    location=azure_location,
    disk_name="vm2-disk",
    sku=azure_native.compute.DiskSkuArgs(name="Standard_LRS"),
    disk_size_gb=32,
    creation_data=azure_native.compute.CreationDataArgs(create_option="Empty"))

# VM1 erstellen
vm1 = azure_native.compute.VirtualMachine(
    "vm1",
    resource_group_name=resource_group.name,
    vm_name=resource_group.name.apply(lambda name: f"{name}-vm1"),
    network_profile=azure_native.compute.NetworkProfileArgs(
        network_interfaces=[azure_native.compute.NetworkInterfaceReferenceArgs(
            id=nic1.id
        )]
    ),
    hardware_profile=azure_native.compute.HardwareProfileArgs(vm_size="Standard_B2s"),
    storage_profile=azure_native.compute.StorageProfileArgs(
        os_disk=azure_native.compute.OSDiskArgs(create_option="FromImage"),
        data_disks=[azure_native.compute.DataDiskArgs(
            lun=0,
            create_option="Attach",
            managed_disk=azure_native.compute.ManagedDiskParametersArgs(id=data_disk1.id)
        )],
        image_reference=azure_native.compute.ImageReferenceArgs(
            publisher="Canonical",
            offer="0001-com-ubuntu-server-jammy",
            sku="22_04-lts",
            version="latest"
        )
    ),
    os_profile=azure_native.compute.OSProfileArgs(
        computer_name="vm1",
        admin_username="azureuser",
        admin_password="GanzGeheim123!"
    ),
    diagnostics_profile=azure_native.compute.DiagnosticsProfileArgs(
        boot_diagnostics=azure_native.compute.BootDiagnosticsArgs(
            enabled=True,
            storage_uri=storage_account_uri
        )
    )
)

# VM2 erstellen
vm2 = azure_native.compute.VirtualMachine(
    "vm2",
    resource_group_name=resource_group.name,
    vm_name=resource_group.name.apply(lambda name: f"{name}-vm2"),
    network_profile=azure_native.compute.NetworkProfileArgs(
        network_interfaces=[azure_native.compute.NetworkInterfaceReferenceArgs(
            id=nic2.id
        )]
    ),
    hardware_profile=azure_native.compute.HardwareProfileArgs(vm_size="Standard_B2s"),
    storage_profile=azure_native.compute.StorageProfileArgs(
        os_disk=azure_native.compute.OSDiskArgs(create_option="FromImage"),
        data_disks=[azure_native.compute.DataDiskArgs(
            lun=0,
            create_option="Attach",
            managed_disk=azure_native.compute.ManagedDiskParametersArgs(id=data_disk2.id)
        )],
        image_reference=azure_native.compute.ImageReferenceArgs(
            publisher="Canonical",
            offer="0001-com-ubuntu-server-jammy",
            sku="22_04-lts",
            version="latest"
        )
    ),
    os_profile=azure_native.compute.OSProfileArgs(
        computer_name="vm2",
        admin_username="azureuser",
        admin_password="GanzGeheim123!"
    ),
    diagnostics_profile=azure_native.compute.DiagnosticsProfileArgs(
        boot_diagnostics=azure_native.compute.BootDiagnosticsArgs(
            enabled=True,
            storage_uri=storage_account_uri
        )
    )
)

# VM-Erweiterungen für die Installation von NGINX
vm1_extension = azure_native.compute.VirtualMachineExtension("vm1Extension",
    resource_group_name=resource_group.name,
    vm_name=vm1.name,
    vm_extension_name="installNginx",
    publisher="Microsoft.Azure.Extensions",
    type="CustomScript",
    type_handler_version="2.1",
    auto_upgrade_minor_version=True,
    settings={
        "commandToExecute": "sudo apt-get update && sudo apt-get install -y nginx && "
                            "echo '<head><title>Hello World 1</title></head><body><h1>Web Portal</h1>"
                            "<p>Hello World 1</p></body>' | sudo tee /var/www/html/index.nginx-debian.html && "
                            "sudo systemctl restart nginx"
    })

vm2_extension = azure_native.compute.VirtualMachineExtension("vm2Extension",
    resource_group_name=resource_group.name,
    vm_name=vm2.name,
    vm_extension_name="installNginx",
    publisher="Microsoft.Azure.Extensions",
    type="CustomScript",
    type_handler_version="2.1",
    auto_upgrade_minor_version=True,
    settings={
        "commandToExecute": "sudo apt-get update && sudo apt-get install -y nginx && "
                            "echo '<head><title>Hello World 2</title></head><body><h1>Web Portal</h1>"
                            "<p>Hello World 2</p></body>' | sudo tee /var/www/html/index.nginx-debian.html && "
                            "sudo systemctl restart nginx"
    })
metric_alert = insights.MetricAlert(
   "highCpuMetricAlertVm1",
    resource_group_name=resource_group.name,
    description="Alarm bei hoher CPU-Auslastung",
    location="global",  # Standort auf 'global' festlegen
    severity=2,
    enabled=True,
    scopes=[vm1.id],  # Scope auf die VM (vm1) setzen
    window_size="PT5M",
    evaluation_frequency="PT1M",  # Korrektes Argument
    criteria=insights.MetricAlertSingleResourceMultipleMetricCriteriaArgs(
        odata_type="Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
        all_of=[
            insights.MetricCriteriaArgs(
                name="HighCPUUsage",
                metric_name="Percentage CPU",
                metric_namespace="microsoft.compute/virtualmachines",
                operator="GreaterThan",
                threshold=80,
                time_aggregation="Average",
                dimensions=[],
                criterion_type="StaticThresholdCriterion"
            ),
        ]
    ),
    actions=[],
)

metric_alert = insights.MetricAlert(
   "highCpuMetricAlertVm2",
    resource_group_name=resource_group.name,
    description="Alarm bei hoher CPU-Auslastung",
    location="global",  # Standort auf 'global' festlegen
    severity=2,
    enabled=True,
    scopes=[vm2.id],  # Scope auf die VM (vm1) setzen
    window_size="PT5M",
    evaluation_frequency="PT1M",  # Korrektes Argument
    criteria=insights.MetricAlertSingleResourceMultipleMetricCriteriaArgs(
        odata_type="Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
        all_of=[
            insights.MetricCriteriaArgs(
                name="HighCPUUsage",
                metric_name="Percentage CPU",
                metric_namespace="microsoft.compute/virtualmachines",
                operator="GreaterThan",
                threshold=80,
                time_aggregation="Average",
                dimensions=[],
                criterion_type="StaticThresholdCriterion"
            ),
        ]
    ),
    actions=[],
)

# Exportieren der Ergebnisse
pulumi.export("publicIpAddress", public_ip.ip_address)
pulumi.export("logAnalyticsWorkspaceId", log_analytics_workspace.id)