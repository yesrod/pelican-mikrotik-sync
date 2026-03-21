#!/usr/bin/env python3
import json
import logging
import os
import requests

from dataclasses import asdict, dataclass
from requests.auth import HTTPBasicAuth
from typing import Any, Dict, List, Literal, Optional, Type, TypeVar


PELICAN_API_KEY = os.getenv('PELICAN_API_KEY')
PELICAN_API_BASE_URL = os.getenv('PELICAN_API_BASE_URL', '')
MIKROTIK_API_BASE_URL = os.getenv('MIKROTIK_API_BASE_URL', '')
MIKROTIK_API_USERNAME = os.getenv('MIKROTIK_API_USERNAME')
MIKROTIK_API_PASSWORD = os.getenv('MIKROTIK_API_PASSWORD')
MIKROTIK_API_RULE_IDENTIFIER = os.getenv('MIKROTIK_API_RULE_IDENTIFIER', 'Pelican-to-Mikrotik')
MIKROTIK_API_RULE_TEMPLATE = os.getenv('MIKROTIK_API_RULE_TEMPLATE', '{}')

def trace(message: str):
    logging.log(5, message)

S = TypeVar("S", bound="Server")
@dataclass
class Server:
    id: int
    name: str

    @classmethod
    def get_server(cls: Type[S], server_id: int) -> S:
        server_data = http_client.get(f"/api/application/servers/{server_id}")
        logging.debug(f"{server_data=}")
        return cls(id=server_data['attributes']['id'], name=server_data['attributes']['name'])

    @classmethod
    def get_servers_list(cls: Type[S]) -> List[S]:
        server_data = http_client.get("/api/application/servers/")
        logging.debug(f"{server_data=}")
        return [cls(id=int(s['attributes']['id']), name=s['attributes']['name']) for s in server_data]

N = TypeVar("N", bound="Node")
@dataclass
class Node:
    name: str
    id: int
    fqdn: str

    @classmethod
    def get_node(cls: Type[N], node_id: int) -> N:
        node_data = http_client.get(f"/api/application/nodes/{node_id}")['attributes']
        logging.debug(f"{node_data=}")
        return cls(name=node_data['name'], id=int(node_data['id']), fqdn=node_data['fqdn'])

    @classmethod
    def get_nodes_list(cls) -> List["Node"]:
        node_data = http_client.get("/api/application/nodes/")
        logging.debug(f"{node_data=}")
        return [cls(name=n['attributes']['name'],
                    id=int(n['attributes']['id']),
                    fqdn=n['attributes']['fqdn']) 
            for n in node_data]

    @classmethod
    def get_nodes_id_list(cls) -> List[int]:
        node_list_data = cls.get_nodes_list()
        logging.debug(f'{node_list_data=}')
        return [int(n.id) for n in node_list_data]

A = TypeVar("A", bound="Allocation")
@dataclass
class Allocation:
    _node_id: int
    alias: Optional[str]
    assigned: bool
    id: str
    ip: str
    port: int
    notes: str
    _server_id: Optional[int]

    @property
    def node(self) -> Node:
        return Node.get_node(self._node_id)

    @property
    def server(self) -> Optional[Server]:
        return Server.get_server(self._server_id) if self._server_id is not None else None

    @classmethod
    def get_allocations_list(
        cls: Type[A], node_id: int
    ) -> List[A]:
        allocation_list = http_client.get(f'/api/application/nodes/{node_id}/allocations?include=server')
        return_list = []
        for a in allocation_list:
            server_id = None
            try:
                relationship_data = a['attributes'].pop('relationships')
                logging.debug(f"{relationship_data=}")
                try:
                    server_data = relationship_data.pop('server')['attributes']
                    logging.debug(f"{server_data=}")
                    if server_data is not None:
                        server_id = int(server_data['id'])
                except KeyError:
                    logging.debug(f"no server relationship data in allocation {a['attributes']['id']}")
            except KeyError:
                logging.debug(f"no relationship data in allocation {a['attributes']['id']}")
            logging.debug(f"{a['attributes']=}")
            return_list.append(cls(
                **a['attributes'],
                _node_id=node_id,
                _server_id=server_id))
        return return_list

    @classmethod
    def get_active_allocations_list(
        cls: Type[A], node_id: int
    ) -> List[A]:
        return sorted([a for a in cls.get_allocations_list(node_id) if a.assigned],
            key=lambda allocation: allocation._node_id)

    def build_comment(self) -> str:
        return (f"{self.node.name}"
                f"{f'-{self.server.name}' if self.server is not None else ''}"
                f"-{self.alias if self.alias is not None else f'{self.ip}:{self.port}'}")

    def as_mikrotik_rule(self, protocol: Literal['tcp', 'udp']) -> "NATRule":
        new_rule = NATRule.build_template()
        new_rule.protocol = protocol
        new_rule.to_addresses = self.ip
        new_rule.to_ports = str(self.port)
        new_rule.dst_port = str(self.port)
        new_rule.comment = self.build_comment()
        return new_rule

R = TypeVar("R", bound="NATRule")
@dataclass
class NATRule:
    id: str
    chain: str
    action: str
    address_list: Optional[str] = None
    address_list_timeout: Optional[str] = None
    bytes: Optional[str] = None
    comment: Optional[str] = None
    connection_bytes: Optional[str] = None
    connection_limit: Optional[str] = None
    connection_mark: Optional[str] = None
    connection_rate: Optional[str] = None
    connection_type: Optional[str] = None
    content: Optional[str] = None
    copy_from: Optional[str] = None
    disabled: Optional[str] = None
    dynamic: Optional[str] = None
    dscp: Optional[str] = None
    dst_address: Optional[str] = None
    dst_address_list: Optional[str] = None
    dst_address_type: Optional[str] = None
    dst_limit: Optional[str] = None
    dst_port: Optional[str] = None
    fragment: Optional[str] = None
    hotspot: Optional[str] = None
    icmp_options: Optional[str] = None
    in_bridge_port: Optional[str] = None
    in_bridge_port_list: Optional[str] = None
    in_interface: Optional[str] = None
    in_interface_list: Optional[str] = None
    ingress_priority: Optional[str] = None
    invalid: Optional[bool] = None
    ipsec_policy: Optional[str] = None
    ipv4_options: Optional[str] = None
    jump_target: Optional[str] = None
    layer7_protocol: Optional[str] = None
    limit: Optional[str] = None
    log: Optional[str] = None
    log_prefix: Optional[str] = None
    nth: Optional[str] = None
    out_bridge_port: Optional[str] = None
    out_bridge_port_list: Optional[str] = None
    out_interface: Optional[str] = None
    out_interface_list: Optional[str] = None
    packets: Optional[str] = None
    packet_mark: Optional[str] = None
    packet_size: Optional[str] = None
    per_connection_classifier: Optional[str] = None
    place_before: Optional[str] = None
    port: Optional[str] = None
    priority: Optional[str] = None
    protocol: Optional[str] = None
    psd: Optional[str] = None
    random: Optional[str] = None
    randomise_ports: Optional[str] = None
    realm: Optional[str] = None
    routing_mark: Optional[str] = None
    same_not_by_dst: Optional[str] = None
    socks5_port: Optional[str] = None
    socks5_server: Optional[str] = None
    socksify_service: Optional[str] = None
    src_address: Optional[str] = None
    src_address_list: Optional[str] = None
    src_address_type: Optional[str] = None
    src_mac_address: Optional[str] = None
    src_port: Optional[str] = None
    tcp_mss: Optional[str] = None
    time: Optional[str] = None
    to_addresses: Optional[str] = None
    to_ports: Optional[str] = None
    ttl: Optional[str] = None

    # def __init__(self, id: str, action: str, chain: str, **kwargs):
    #     self.id = id
    #     self.action = action
    #     self.chain = chain
    #     for k, v in kwargs.items():
    #         setattr(self, k, v)

    # def __repr__(self):
    #     return f"NATRule({', '.join([k + '=' + v for k, v in self.__dict__.items()])})"

    @classmethod
    def from_dict(cls: Type[R], data: Dict[str, Any]) -> R:
        logging.debug(f"{data=}")
        new_dict = {}
        for k, v in data.items():
            new_dict[k.replace('-', '_').removeprefix('.')] = v
        logging.debug(f"{new_dict=}")
        return cls(**new_dict)

    @classmethod
    def build_template(cls: Type[R]) -> R:
        template_rule = cls(id="TEMPLATE", action="dst-nat", chain="dstnat")
        try:
            template_args = json.loads(MIKROTIK_API_RULE_TEMPLATE)
            if not isinstance(template_args, dict):
                logging.warning(f"Mikrotik rule template should be a JSON dictionary, got {type(template_args).__name__}")
            else:
                for k, v in template_args.items():
                    if k not in ["to_addresses", "to_ports", "dst_port"]:
                        setattr(template_rule, k, v)
                    else:
                        logging.debug(f"not setting {k} in template rule")
        except json.JSONDecodeError:
            logging.error(f"Could not decode MIKROTIK_API_RULE_TEMPLATE")
        
        return template_rule

    def match(self, other_rule: "NATRule", exclude: List[str]) -> bool:
        problem_attributes = ['bytes', 'log', 'log_prefix', 'dynamic', 'packets'] + exclude
        me = asdict(self)
        other = asdict(other_rule)
        for p in problem_attributes:
            me.pop(p)
            other.pop(p)
        logging.info(f"{set(me) ^ set(other)}")
        return set(me) == set(other)

    def match_without_enablement(self, other_rule: "NATRule"):
        return self.match(other_rule, exclude=['disabled'])

    def match_without_comment(self, other_rule: "NATRule") -> bool:
        return self.match(other_rule, exclude=['comment'])

    def match_without_id(self, other_rule: "NATRule") -> bool:
        return self.match(other_rule, exclude=['id'])

class HTTPClient:
    def __init__(self,
        base_url: str = PELICAN_API_BASE_URL,
        api_key: Optional[str] = PELICAN_API_KEY,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        self.base_url = base_url
        if username is not None and password is not None:
            self.basic_auth = HTTPBasicAuth(username, password)
            self.api_key = None
        else:
            self.basic_auth = None
            self.api_key = api_key

    def _request(self, method: str, path: str) -> Any:
        headers = {
            'Content-type': 'application/json'
        }
        if self.api_key is not None:
            headers['Authorization'] = f'Bearer {PELICAN_API_KEY}'
        request_data = requests.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            auth=self.basic_auth
        )
        trace(f"{request_data=} {request_data.text=}")
        request_data.raise_for_status()
        return request_data.json()

    def _request_with_pages(self, method: str, path: str) -> Any:
        request_data = self._request(method, path)
        trace(f"{request_data=}")
        if 'data' in request_data.keys():
            return_data = request_data['data']
        else:
            return_data = request_data
        trace(f'{return_data=}')
        try:
            meta_data = request_data.pop('meta')
            trace(f'{meta_data=}')
            try:
                pagination_data = meta_data.pop('pagination')
                trace(f'{pagination_data=}')
                if '?' in path:
                    q = '&'
                else:
                    q = '?'
                for p in range(2, int(pagination_data['total_pages']) + 1):
                    next_page_data = self._request('GET', f"{path}{q}page={p}")['data']
                    trace(f'{p=} {next_page_data=}')
                    return_data.extend(next_page_data)
            except KeyError:
                trace('no pagination data in metadata')
        except KeyError:
            trace('no metadata in request')
        return return_data

    def get(self, path: str, paginated: bool = True) -> Any:
        if paginated:
            request = self._request_with_pages
        else:
            request = self._request
        return request('GET', f"{path}")

http_client = HTTPClient(
        PELICAN_API_BASE_URL,
        api_key=PELICAN_API_KEY
    )

# class PelicanClient:
#     def __init__(self, http_client: HTTPClient):
#         self.http_client = http_client

class MikrotikClient:
    http_client: HTTPClient
    rule_template: "NATRule"

    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    def get_nat_rules(self) -> List[NATRule]:
        nat_rule_data = self.http_client.get('/rest/ip/firewall/nat', paginated=False)
        return_list = []
        for n in nat_rule_data:
            return_list.append(NATRule.from_dict(n))
        return return_list
    
    def add_nat_rule(self):
        raise NotImplementedError

    def remove_nat_rule(self):
        raise NotImplementedError

    def get_nat_rule_by_ip_and_port(self, ip: str, port: int) -> List[NATRule]:
        #raise NotImplementedError
        # Parameter overlap with Pelican allocation:
        # ip address:
        #  to_addresses
        # port
        #  dst_port
        #  to_ports
        return_list = []
        for nat_rule in self.get_nat_rules():
            if (
                nat_rule.to_addresses == ip
                and nat_rule.dst_port == str(port)
                and nat_rule.to_ports == str(port)
            ):
                logging.debug(f"adding rule {nat_rule}")
                return_list.append(nat_rule)
        return return_list

mikrotik_client = MikrotikClient(
    HTTPClient(
        MIKROTIK_API_BASE_URL,
        username=MIKROTIK_API_USERNAME,
        password=MIKROTIK_API_PASSWORD
    ))

def __main__():
    rule_list = mikrotik_client.get_nat_rules()
    allocation_dict: Dict[int, List[Allocation]] = {}
    for n in Node.get_nodes_id_list():
        allocation_dict[n] = Allocation.get_active_allocations_list(n)
    for node_id, allocations in allocation_dict.items():
        node = Node.get_node(node_id)
        print(f"Allocations for node {node.name} ({node.id}):")
        for a in allocations:
            allocation_rules = []
            allocation_rules.append(a.as_mikrotik_rule(protocol='tcp'))
            allocation_rules.append(a.as_mikrotik_rule(protocol='udp'))

            logging.info(f"{a.alias=} {a.assigned=} {a.id=} {a.ip=} {a.notes=} {a.port=} {a._node_id=} {a._server_id=}")

            for allocation_rule in allocation_rules:
                found = False
                for r in rule_list:
                    # if allocation exists as rule exactly, do nothing
                    #   - magic string in comment
                    #   - allocation alias in comment, if any
                    #   - server name in comment, if any
                    #   - ip and port match
                    #   - template values match
                    if allocation_rule.match_without_id(r):
                        logging.info(f"{allocation_rule.protocol.upper()} rule for allocation {a.id} already present, doing nothing")
                        found = True
                        break

                    # if allocation exists as rule, but doesn't have correct comment, update comment
                    #   - ip and port match
                    #   - template values match
                    #   - comment is not correct format
                
                    #logging.warning(f"\n{allocation_rule=}\n{r=}\n")
                    if allocation_rule.match_without_comment(r):
                        logging.info(f"{allocation_rule.protocol.upper()} rule for allocation {a.id} already present but needs comment update")
                        found = True
                        break

                    # if rule exists, but one of ip, port, or template values doesn't match, do nothing and warn
                    partial_matches = mikrotik_client.get_nat_rule_by_ip_and_port(a.ip, a.port)
                    if len(partial_matches) != 0:
                        logging.warning(f"{allocation_rule.protocol.upper()} partial match rule for allocation {a.id} found, doing nothing to prevent breakage")
                        found = True
                        break

                if found == True:
                    continue

                # if rule does not exist, add it
                logging.info(f"Adding {allocation_rule.protocol.upper()} rule for allocation {a}")


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv('LOG_LEVEL', 'INFO'),
        format="%(levelname)s:%(name)s:%(funcName)s:%(lineno)d:%(message)s"
    )
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    __main__()