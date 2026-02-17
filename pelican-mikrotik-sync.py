#!/usr/bin/env python3
import logging
import os
import requests

from dataclasses import dataclass
from requests.auth import HTTPBasicAuth
from typing import Any, Dict, List, Optional


PELICAN_API_KEY = os.getenv('PELICAN_API_KEY')
PELICAN_API_BASE_URL = os.getenv('PELICAN_API_BASE_URL', '')
MIKROTIK_API_BASE_URL = os.getenv('MIKROTIK_API_BASE_URL', '')
MIKROTIK_API_USERNAME = os.getenv('MIKROTIK_API_USERNAME')
MIKROTIK_API_PASSWORD = os.getenv('MIKROTIK_API_PASSWORD')
MIKROTIK_API_RULE_IDENTIFIER = os.getenv('MIKROTIK_API_RULE_IDENTIFIER', 'Pelican-to-Mikrotik')


class HTTPClient:
    def __init__(self,
        base_url: str = PELICAN_API_BASE_URL,
        username: Optional[str] = None,
        password: Optional[str] = None
    ):
        self.base_url = base_url
        if username is not None and password is not None:
            self.basic_auth = HTTPBasicAuth(username, password)
        else:
            self.basic_auth = None

    def _request(self, method: str, path: str) -> Any:
        request_data = requests.request(
            method,
            f"{self.base_url}{path}",
            headers={
                'Authorization': f'Bearer {PELICAN_API_KEY}',
                'Content-type': 'application/json'
            },
            auth=self.basic_auth
        )
        logging.debug(f"{request_data=} {request_data.text=}")
        return request_data.json()

    def _request_with_pages(self, method: str, path: str) -> Any:
        request_data = self._request(method, path)
        logging.debug(f"{request_data=}")
        if 'data' in request_data.keys():
            return_data = request_data['data']
        else:
            return_data = request_data
        logging.debug(f'{return_data=}')
        try:
            meta_data = request_data.pop('meta')
            logging.debug(f'{meta_data=}')
            try:
                pagination_data = meta_data.pop('pagination')
                logging.debug(f'{pagination_data=}')
                if '?' in path:
                    q = '&'
                else:
                    q = '?'
                for p in range(2, int(pagination_data['total_pages']) + 1):
                    next_page_data = self._request('GET', f"{path}{q}page={p}")['data']
                    logging.debug(f'{p=} {next_page_data=}')
                    return_data.extend(next_page_data)
            except KeyError:
                logging.debug('no pagination data in metadata')
        except KeyError:
            logging.debug('no metadata in request')
        return return_data

    def get(self, path: str, paginated: bool = True) -> Any:
        if paginated:
            request = self._request_with_pages
        else:
            request = self._request
        return request('GET', f"{path}")

class PelicanClient:
    def __init__(self):
        self.http_client = HTTPClient()

    @dataclass
    class Server:
        name: str

    @dataclass
    class Allocation:
        node_id: int
        alias: Optional[str]
        assigned: bool
        id: str
        ip: str
        port: int
        notes: str
        server_id: Optional[int]
        server_name: Optional[str]

    @dataclass
    class Node:
        name: str
        id: int
        fqdn: str

    def get_node(self, node_id: int) -> Any:
        node_data = self.http_client.get(f"/api/application/nodes/{node_id}")['attributes']
        return self.Node(name=node_data['name'], id=int(node_data['id']), fqdn=node_data['fqdn'])

    def get_nodes_list(self) -> List[Any]:
        return self.http_client.get("/api/application/nodes/")

    def get_nodes_id_list(self) -> List[int]:
        node_list_data = self.get_nodes_list()
        logging.debug(f'{node_list_data=}')
        return [int(n['attributes']['id']) for n in node_list_data]

    def get_server(self, server_id: int) -> Any:
        server_data = self.http_client.get(f"/api/application/servers/{server_id}")
        return server_data

    def get_servers_list(self) -> List[Any]:
        server_data = self.http_client.get("/api/application/servers/")
        logging.debug(f"{server_data=}")
        return server_data

    def get_allocations_list(self, node_id: int) -> List[Allocation]:
        allocation_list = self.http_client.get(f'/api/application/nodes/{node_id}/allocations?include=server')
        return_list = []
        for a in allocation_list:
            server_id = None
            server_name = None
            try:
                relationship_data = a['attributes'].pop('relationships')
                logging.debug(f"{relationship_data=}")
                try:
                    server_data = relationship_data.pop('server')['attributes']
                    logging.debug(f"{server_data=}")
                    if server_data is not None:
                        server_id = server_data['id']
                        server_name = server_data['name']
                except KeyError:
                    logging.debug(f"no server relationship data in allocation {a['attributes']['id']}")
            except KeyError:
                logging.debug(f"no relationship data in allocation {a['attributes']['id']}")
            logging.debug(f"{a['attributes']=}")
            return_list.append(self.Allocation(
                **a['attributes'],
                node_id=node_id,
                server_id=server_id,
                server_name=server_name))
        return return_list

    def get_active_allocations_list(self, node_id: int) -> List[Allocation]:
        return sorted([a for a in self.get_allocations_list(node_id) if a.assigned],
            key=lambda allocation: allocation.server_id)    # pyright: ignore[reportCallIssue,reportArgumentType]

class MikrotikClient:
    def __init__(self):
        self.http_client = HTTPClient(
            MIKROTIK_API_BASE_URL,
            username=MIKROTIK_API_USERNAME,
            password=MIKROTIK_API_PASSWORD
        )

    class NATRule:
        id: str
        chain: str
        action: str
        # address_list: Optional[str] = None
        # address_list_timeout: Optional[str] = None
        # bytes: Optional[str] = None
        # comment: Optional[str] = None
        # connection_bytes: Optional[str] = None
        # connection_limit: Optional[str] = None
        # connection_mark: Optional[str] = None
        # connection_rate: Optional[str] = None
        # connection_type: Optional[str] = None
        # content: Optional[str] = None
        # copy_from: Optional[str] = None
        # disabled: Optional[str] = None
        # dynamic: Optional[str] = None
        # dscp: Optional[str] = None
        # dst_address: Optional[str] = None
        # dst_address_list: Optional[str] = None
        # dst_address_type: Optional[str] = None
        # dst_limit: Optional[str] = None
        # dst_port: Optional[str] = None
        # fragment: Optional[str] = None
        # hotspot: Optional[str] = None
        # icmp_options: Optional[str] = None
        # in_bridge_port: Optional[str] = None
        # in_bridge_port_list: Optional[str] = None
        # in_interface: Optional[str] = None
        # in_interface_list: Optional[str] = None
        # ingress_priority: Optional[str] = None
        # invalid: Optional[bool] = None
        # ipsec_policy: Optional[str] = None
        # ipv4_options: Optional[str] = None
        # jump_target: Optional[str] = None
        # layer7_protocol: Optional[str] = None
        # limit: Optional[str] = None
        # log: Optional[str] = None
        # log_prefix: Optional[str] = None
        # nth: Optional[str] = None
        # out_bridge_port: Optional[str] = None
        # out_bridge_port_list: Optional[str] = None
        # out_interface: Optional[str] = None
        # out_interface_list: Optional[str] = None
        # packets: Optional[str] = None
        # packet_mark: Optional[str] = None
        # packet_size: Optional[str] = None
        # per_connection_classifier: Optional[str] = None
        # place_before: Optional[str] = None
        # port: Optional[str] = None
        # priority: Optional[str] = None
        # protocol: Optional[str] = None
        # psd: Optional[str] = None
        # random: Optional[str] = None
        # randomise_ports: Optional[str] = None
        # realm: Optional[str] = None
        # routing_mark: Optional[str] = None
        # same_not_by_dst: Optional[str] = None
        # socks5_port: Optional[str] = None
        # socks5_server: Optional[str] = None
        # socksify_service: Optional[str] = None
        # src_address: Optional[str] = None
        # src_address_list: Optional[str] = None
        # src_address_type: Optional[str] = None
        # src_mac_address: Optional[str] = None
        # src_port: Optional[str] = None
        # tcp_mss: Optional[str] = None
        # time: Optional[str] = None
        # to_addresses: Optional[str] = None
        # to_ports: Optional[str] = None
        # ttl: Optional[str] = None

        def __init__(self, id: str, action: str, chain: str, **kwargs):
            self.id = id
            self.action = action
            self.chain = chain
            for k, v in kwargs.items():
                setattr(self, k, v)

        def __repr__(self):
            return f"NATRule({', '.join([k + '=' + v for k, v in self.__dict__.items()])})"

        @classmethod
        def from_dict(cls, data: Dict[str, Any]):
            logging.warning(f"{data=}")
            new_dict = {}
            for k, v in data.items():
                new_dict[k.replace('-', '_').removeprefix('.')] = v
            logging.warning(f"{new_dict=}")
            return cls(**new_dict)

    def get_nat_rules(self) -> List[NATRule]:
        nat_rule_data = self.http_client.get('/rest/ip/firewall/nat', paginated=False)
        return_list = []
        for n in nat_rule_data:
            return_list.append(self.NATRule.from_dict(n))
        return return_list
    
    def add_nat_rule(self):
        raise NotImplementedError

    def remove_nat_rule(self):
        raise NotImplementedError

def __main__():
    pelican_client = PelicanClient()
    mikrotik_client = MikrotikClient()
    allocation_dict = {}
    for n in pelican_client.get_nodes_id_list():
        allocation_dict[n] = pelican_client.get_active_allocations_list(n)
    for node_id, allocations in allocation_dict.items():
        node = pelican_client.get_node(node_id)
        print(f"Allocations for node {node.name} ({node.id}):")
        for a in allocations:
            print(f"  {a.ip}:{a.port}{' (alias ' + a.alias + ')' if a.alias else ''}{' (server ' + str(a.server_name) + ')' if a.server_name else ''}")

    import pprint
    pprint.pprint(mikrotik_client.get_nat_rules())


if __name__ == "__main__":
    logging.getLogger().setLevel(os.getenv('PELICAN_API_LOG_LEVEL', 'INFO'))
    __main__()