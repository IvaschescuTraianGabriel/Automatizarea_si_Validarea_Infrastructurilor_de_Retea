import ipaddress
import logging
from pyats.aetest.steps import Steps
from connectors.swagger_connector import SwaggerConnector
from genie.conf.base import Device

log = logging.getLogger(__name__)


class ConfigurationFTD:
    def __init__(self, swagger: SwaggerConnector, device: Device):
        self.swagger = swagger
        self.device = device
        self.sz_refs = []

    def configure(self, steps: Steps):
        self.configure_interfaces(steps) # to be modified
        self.configure_security_zones(steps)
        self.create_access_rule(steps)
        # self.deploy_configuration(steps)

    def configure_interfaces(self, steps: Steps):
        with steps.start("Configure physical interfaces Gig0/2 and Gig0/4"):
            interfaces = self.swagger.client.Interface.getPhysicalInterfaceList().result()['items']

            # Target only the specific interfaces
            target_interfaces = ['GigabitEthernet0/2', 'GigabitEthernet0/4']

            for obj in interfaces:
                if obj.hardwareName in target_interfaces and obj.hardwareName in self.device.interfaces:
                    intf_data = self.device.interfaces[obj.hardwareName]
                    ip = intf_data.ipv4.ip
                    mask = intf_data.ipv4.netmask

                    obj.enabled = True
                    obj.linkState = "UP"
                    obj.name = intf_data.alias or obj.hardwareName
                    obj.ipv4.dhcp = False
                    obj.ipv4.ipType = "STATIC"

                    # Ensure ipAddress object is initialized
                    if not getattr(obj.ipv4, 'ipAddress', None):
                        try:
                            ip_model = self.swagger.client.get_model('IPv4Address')
                            obj.ipv4.ipAddress = ip_model()
                        except Exception as e:
                            log.error(f"Failed to get IP address model: {e}")
                            continue

                    obj.ipv4.ipAddress.ipAddress = ip.compressed
                    obj.ipv4.ipAddress.netmask = mask.compressed

                    res = self.swagger.client.Interface.editPhysicalInterface(objId=obj.id, body=obj).result()
                    log.info(f"Updated interface {obj.hardwareName}: {res}")


    def configure_security_zones(self, steps: Steps):
        with steps.start('Configure security zones'):
            ref = self.swagger.client.get_model('ReferenceModel')
            intfs = self.swagger.client.Interface.getPhysicalInterfaceList().result()['items']
            # Only include the specific interfaces
            target_intfs = ['GigabitEthernet0/2', 'GigabitEthernet0/4']

            for obj in intfs:
                if obj.hardwareName not in target_intfs:
                    continue

                sz_model = self.swagger.client.get_model('SecurityZone')
                zone_name = 'SecZoneOutside' if obj.hardwareName == 'GigabitEthernet0/2' else 'SecZoneInside'
                sz = sz_model(
                    name=zone_name,
                    mode='ROUTED',
                    interfaces=[ref(id=obj.id, name=obj.name, hardwareName=obj.hardwareName, type=obj.type)]
                )
                result = self.swagger.client.SecurityZone.addSecurityZone(body=sz).result()
                log.info(f"Created SecurityZone: {result}")

                self.sz_refs.append(ref(id=result['id'], name=result['name'], type='securityzone'))

    def create_access_rule(self, steps: Steps):
        with steps.start('Creating Access Rule'):
            out = self.swagger.client.AccessPolicy.getAccessPolicyList()
            model = self.swagger.client.get_model('AccessRule')
            res = self.swagger.client.AccessPolicy.addAccessRule(
                parentId=out.result().items[0].id,
                body=model(
                    name='Allow_ICMP_Traffic',
                    ruleAction='PERMIT',
                    eventLogAction='LOG_NONE',
                    sourceZones=[self.sz_refs[0]],  # First zone as source
                    destinationZones=[self.sz_refs[1]], # Second zone as destination
                    embeddedAppFilter={
                        'type': 'embeddedappfilter',
                        'applications': [
                            {
                                'name': 'ICMP',
                                'appId': 3501,
                                'id': '26299d7b-5145-11f0-a7f2-d1426bbb9af6',
                                'type': 'application'
                            }
                        ],
                        'applicationFilters': [],
                        'conditions': []
                    }
                )
            )
            print(res.result())

    # def deploy_configuration(self, steps: Steps):
    #     with steps.start('Deploy FTD configuration'):
    #         response = self.swagger.client.Deployment.addDeployment().result()
    #         for _ in range(10):
    #             status = self.swagger.client.Deployment.getDeployment(objId=response.id).result()
    #             msg = status['deploymentStatusMessages'][-1]
    #             if msg['taskState'] == "FINISHED":
    #                 log.info("Deployment completed successfully")
    #                 return
    #         raise Exception("Deployment did not finish in time")