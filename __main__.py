import pulumi
import pulumi_azure_native as azure_native
import uuid
from pulumi_azure_native import resources, network, compute, storage, operationalinsights, insights, authorization
import pulumi_azuread as azuread


# Konfigurationseinstellungen laden
config = pulumi.Config()
azure_location = config.get("azure-native:location") or "uksouth"
email_gregoire = "wi22b060@technikum-wien.at"
email_matthias = "wi22b112@technikum-wien.at"

# Ressourcengruppe erstellen
resource_group = azure_native.resources.ResourceGroup("IaaSResourceGroup", resource_group_name="IaaSResourceGroup")
user_gregoire = azuread.get_user(user_principal_name=email_gregoire)
user_matthias = azuread.get_user(user_principal_name=email_matthias)

def assign_reader_role(user_object_id, resource_group, role_name_suffix):
    role_assignment_name = str(uuid.uuid4())
    role_assignment = authorization.RoleAssignment(
        f"readerRoleAssignment-{role_name_suffix}-{role_assignment_name}",
        scope=resource_group.id,
        role_assignment_name=role_assignment_name,
        principal_id=user_object_id,
        role_definition_id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/providers/Microsoft.Authorization/roleDefinitions/{pulumi.Config().require('readerRoleDefinitionId')}",
        principal_type="User",
        opts=pulumi.ResourceOptions(ignore_changes=["role_definition_id"])
    )
    return role_assignment.id

role_assignment_id_gregoire = assign_reader_role(user_gregoire.object_id, resource_group, "gregoire")
role_assignment_id_matthias = assign_reader_role(user_matthias.object_id, resource_group, "matthias")


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
# Subnetz erstellen
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
    public_ip_address_name="IaaSPublicIP",
    sku=azure_native.network.PublicIPAddressSkuArgs(name="Standard"),
    public_ip_allocation_method="Static",
    zones=["1", "2", "3"]
)

# Load Balancer erstellen
load_balancer = azure_native.network.LoadBalancer("loadBalancer",
    resource_group_name=resource_group.name,
    location=azure_location,  
    load_balancer_name="IaaSLoadBalancer",
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
            id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/resourceGroups/IaaSResourceGroup/providers/Microsoft.Network/loadBalancers/IaaSLoadBalancer/frontendIPConfigurations/myFrontEnd"
        ),
        backend_address_pool=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/resourceGroups/IaaSResourceGroup/providers/Microsoft.Network/loadBalancers/IaaSLoadBalancer/backendAddressPools/myBackEndPool"
        ),
        probe=azure_native.network.SubResourceArgs(
            id=f"/subscriptions/{pulumi.Config().require('subscription_id')}/resourceGroups/IaaSResourceGroup/providers/Microsoft.Network/loadBalancers/IaaSLoadBalancer/probes/httpProbe"
        ),
        protocol="Tcp",
        frontend_port=80,
        backend_port=80,
        enable_floating_ip=False,
        idle_timeout_in_minutes=4,
        load_distribution="Default"
    )])

action_group = azure_native.insights.ActionGroup(
    "ActionGroup",
    resource_group_name=resource_group.name,
    location="global",
    action_group_name="ActionGroup",
    group_short_name="AG",
    email_receivers=[azure_native.insights.EmailReceiverArgs(
        name="ADMIN",
        email_address="wi22b060@technikum-wien.at",
        use_common_alert_schema=True
    )]
)

# VM-Einstellungen definieren
vm_names = ["vm1", "vm2"]
admin_username = "azureuser"
admin_password = "Password@1234"
image_reference = azure_native.compute.ImageReferenceArgs(
    publisher="Canonical",
    offer="0001-com-ubuntu-server-jammy",
    sku="22_04-lts",
    version="latest"
)

for idx, vm_name in enumerate(vm_names):
    # Network Interface erstellen
    nic = azure_native.network.NetworkInterface(f"nic-{vm_name}",
        resource_group_name=resource_group.name,
        ip_configurations=[azure_native.network.NetworkInterfaceIPConfigurationArgs(
            name="ipconfig1",
            subnet=azure_native.network.SubResourceArgs(id=subnet.id),
            private_ip_allocation_method="Dynamic",
            load_balancer_backend_address_pools=[azure_native.network.SubResourceArgs(
                id=load_balancer.backend_address_pools[0].id
            )]
        )],
        network_security_group=azure_native.network.SubResourceArgs(id=network_security_group.id)
    )

    # Data Disk erstellen
    data_disk = azure_native.compute.Disk(f"dataDisk-{vm_name}",
        resource_group_name=resource_group.name,
        location=resource_group.location,
        disk_name=f"{vm_name}-disk",
        sku=azure_native.compute.DiskSkuArgs(name="Standard_LRS"),
        disk_size_gb=32,
        creation_data=azure_native.compute.CreationDataArgs(create_option="Empty")
    )

    # Virtual Machine erstellen
    vm = azure_native.compute.VirtualMachine(vm_name,
        resource_group_name=resource_group.name,
        network_profile=azure_native.compute.NetworkProfileArgs(
            network_interfaces=[azure_native.compute.NetworkInterfaceReferenceArgs(
                id=nic.id
            )]
        ),
        hardware_profile=azure_native.compute.HardwareProfileArgs(vm_size="Standard_B2s"),
        storage_profile=azure_native.compute.StorageProfileArgs(
            os_disk=azure_native.compute.OSDiskArgs(create_option="FromImage"),
            data_disks=[azure_native.compute.DataDiskArgs(
                lun=0,
                create_option="Attach",
                managed_disk=azure_native.compute.ManagedDiskParametersArgs(id=data_disk.id)
            )],
            image_reference=image_reference
        ),
        os_profile=azure_native.compute.OSProfileArgs(
            computer_name=vm_name,
            admin_username=admin_username,
            admin_password=admin_password
        ),
        diagnostics_profile=azure_native.compute.DiagnosticsProfileArgs(
            boot_diagnostics=azure_native.compute.BootDiagnosticsArgs(
                enabled=True,
                storage_uri=storage_account_uri
            )
        )
    )

    # Virtual Machine Extension erstellen
    vm_extension = azure_native.compute.VirtualMachineExtension(f"{vm_name}Extension",
        resource_group_name=resource_group.name,
        vm_name=vm.name,
        publisher="Microsoft.Azure.Extensions",
        type="CustomScript",
        type_handler_version="2.1",
        auto_upgrade_minor_version=True,
        settings={
            "commandToExecute": f"sudo apt-get update && sudo apt-get install -y nginx && "
                                f"echo '<head><title>Hello {vm_name}</title></head><body><h1>Web Portal</h1>"
                                f"<p>Hello {vm_name}</p></body>' | sudo tee /var/www/html/index.nginx-debian.html && "
                                f"sudo systemctl restart nginx"
        }
    )
    # Metric Alert für jede VM
    metric_alert = azure_native.insights.MetricAlert(
        f"highCpuMetricAlert-{vm_name}",
        resource_group_name=resource_group.name,
        description=f"High CPU usage alert for {vm_name}",
        location="global",
        severity=2,
        enabled=True,
        scopes=[vm.id],
        window_size="PT5M",
        evaluation_frequency="PT1M",
        criteria=azure_native.insights.MetricAlertSingleResourceMultipleMetricCriteriaArgs(
            odata_type="Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria",
            all_of=[
                azure_native.insights.MetricCriteriaArgs(
                    name="HighCPUUsage",
                    metric_name="Percentage CPU",
                    metric_namespace="microsoft.compute/virtualmachines",
                    operator="GreaterThan",
                    threshold=80,
                    time_aggregation="Average",
                    dimensions=[],
                    criterion_type="StaticThresholdCriterion"
                )
            ]
        ),
        actions=[
            azure_native.insights.MetricAlertActionArgs(
                action_group_id=action_group.id
            )
        ] ,
        opts=pulumi.ResourceOptions(depends_on=[vm])
    )

# Aktivitätsprotokolle
activity_logs = insights.DiagnosticSetting(
    "activityLogDiagnostics",
    resource_uri=f"/subscriptions/{pulumi.Config().require('subscription_id')}",
    logs=[
        insights.LogSettingsArgs(
            category="Administrative",
            enabled=True,
            retention_policy=insights.RetentionPolicyArgs(enabled=True, days=30),
        ),
        insights.LogSettingsArgs(
            category="Security",
            enabled=True,
            retention_policy=insights.RetentionPolicyArgs(enabled=True, days=30),
        ),
        insights.LogSettingsArgs(
            category="ServiceHealth",
            enabled=True,
            retention_policy=insights.RetentionPolicyArgs(enabled=True, days=30),
        ),
    ],
     metrics=[],
    workspace_id=log_analytics_workspace.id,
    opts=pulumi.ResourceOptions(depends_on=[log_analytics_workspace]) 
)


pulumi.export("publicIpAddress", public_ip.ip_address)
