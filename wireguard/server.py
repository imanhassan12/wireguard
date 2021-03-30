
import os

from subnet import (
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    ip_address,
    ip_network,
)

from .constants import (
    MAX_ADDRESS_RETRIES,
    MAX_PRIVKEY_RETRIES,
)
from .config import ServerConfig
from .peer import Peer


class Server(Peer):

    subnet = None

    def __init__(self,
                 description,
                 subnet,
                 **kwargs
            ):

        if not isinstance(subnet, (IPv4Network, IPv6Network)):
            subnet = ip_network(subnet)

        self.subnet = subnet

        if 'address' not in kwargs:
            kwargs.update({'address': subnet.random_ip()})
        if 'config_cls' not in kwargs:
            kwargs.update({'config_cls': ServerConfig})

        super().__init__(
            description,
            **kwargs
        )

    def __repr__(self):
        """
        A simplistic representation of this object
        """

        return f'<{self.__class__.__name__} iface={self.interface} subnet={self.subnet} address={self.address}>'

    def privkey_exists(self, item):
        """
        Checks a private key against the private keys already used by this server and it's peers
        """

        if item == self.private_key:
            return True

        return item in self.peers_privkeys

    def address_exists(self, item):
        """
        Checks an IP address against the addresses already used by this server and it's peers
        """

        if not isinstance(item, (IPv4Address, IPv6Address)):
            item = ip_address(item)

        if item == self.address:
            return True

        return item in self.peers_addresses

    @property
    def peers_addresses(self):
        if not self.peers:
            return []
        return [peer.address for peer in self.peers]

    @property
    def peers_privkeys(self):
        if not self.peers:
            return []
        return [peer.private_key for peer in self.peers]

    @property
    def peers_pubkeys(self):
        if not self.peers:
            return []
        return [peer.public_key for peer in self.peers]

    def unique_address(self, max_address_retries=None):
        """
        Return an unused address from this server's subnet
        """

        if max_address_retries is None or max_address_retries == True:
            max_address_retries = MAX_ADDRESS_RETRIES

        address = self.subnet.random_ip()
        tries = 0

        while self.address_exists(address):
            if tries >= max_address_retries:
                raise ValueError('Too many retries to obtain an unused IP address')

            address = self.subnet.random_ip()
            tries += 1

        return address

    def unique_privkey(self, max_privkey_retries=None):
        """
        Returns a private key that is not already in use among this server's peers
        """

        if max_privkey_retries is None or max_privkey_retries == True:
            max_privkey_retries = MAX_PRIVKEY_RETRIES

        private_key = generate_key()
        tries = 0

        while self.privkey_exists(private_key):
            if tries >= max_privkey_retries:
                raise ValueError('Too many retries to obtain an unique private key')

            private_key = generate_key()
            tries += 1

        return private_key

    def peer(self,
             description,
             *,
             peer_cls=Peer,
             **kwargs
        ):

        if not callable(peer_cls):
            raise ValueError('Ivalid value given for peer_cls')

        if 'address' not in kwargs:
            kwargs.update({'address': self.unique_address()})

        for key in ['port', 'keepalive', 'interface', 'dns']:
            if key not in kwargs:
                kwargs.update({key: getattr(self, key)})

        peer = peer_cls(
            description,
            **kwargs
        )

        self.add_peer(peer, max_address_retries=(kwargs.get('address') is not None))
        return peer

    def add_peer(self, peer, max_address_retries=None, max_privkey_retries=None):
        """
        Adds a peer to this server, checking for a unique IP address + unique private key
        and optionally updating the peer's data to obtain uniqueness
        """

        if self.address_exists(peer.address):
            try:
                if max_address_retries == False or max_address_retries == 0:
                    raise ValueError('Not allowed to change the peer IP address due to'
                                     ' max_address_retries=False (or 0)')
                peer.address = self.unique_address(max_address_retries)
            except ValueError as exc:
                raise ValueError('Could not add peer to this server. It is not unique.', exc)

        if self.privkey_exists(peer.private_key):
            try:
                if max_privkey_retries == False or max_privkey_retries == 0:
                    raise ValueError('Not allowed to change the peer private key due to'
                                     ' max_privkey_retries=False (or 0)')
                peer.private_key = self.unique_privkey(max_privkey_retries)
            except ValueError as exc:
                raise ValueError('Could not add peer to this server. It is not unique.', exc)

        peer.peers.add(self)  # This server needs to be a peer of the new peer
        self.peers.add(peer)  # The peer needs to be attached to this server

    def add_nat_traversal(self, outbound_interface):
        post_up = [
            f'iptables -A FORWARD -i %i -o {outbound_interface} -j ACCEPT',
            f'iptables -A FORWARD -i {outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
            f'iptables -t nat -A POSTROUTING -o {outbound_interface} -j MASQUERADE',
        ]
        post_down = [
            f'iptables -D FORWARD -i %i -o {outbound_interface} -j ACCEPT',
            f'iptables -D FORWARD -i {outbound_interface} -o %i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT',
            f'iptables -t nat -D POSTROUTING -o {outbound_interface} -j MASQUERADE',
        ]
        self.post_up.extend(post_up)
        self.post_down.extend(post_down)
