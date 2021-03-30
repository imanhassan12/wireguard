
from subnet import (
    ip_address,
    ip_network,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
)


class ClassedSet(set):

    def _coerce_value(self, value):
        raise NotImplemented('ClassedSet must be not be used directly. Inherit from it, with '
                             'appropriate value coersion logic implemented in the child class')

    def add(self, value):
        """
        Adds a value to this collection, maintaining uniqueness
        """

        if not value:
            raise ValueError(f'Cannot add an empty value to {self.__class__}')

        if isinstance(value, list):
            raise ValueError('Provided value must not be a list')

        super().add(self._coerce_value(value))

    def extend(self, values):
        """
        Adds multiple values to this collection, maintaining uniqueness
        """

        if not values:
            raise ValueError(f'Cannot add an empty value to {self.__class__}')

        if not isinstance(values, list):
            values = [values]

        for value in values:
            self.add(value)

class IPAddressSet(ClassedSet):

    def _coerce_value(self, value):
        """
        Coerce given values into an IP Address object
        """

        if not isinstance(value, (IPv4Address, IPv6Address)):
            value = ip_address(value)
        return value


class IPNetworkSet(ClassedSet):

    def _coerce_value(self, value):
        """
        Coerce given values into an IP Network object

        IP address objects/strings will automatically be set to `/32` or `/128` subnets
        by `ip_network()` when no netmask is specified. No special handling is required.
        """

        if not isinstance(value, (IPv4Network, IPv6Network)):
            value = ip_network(value)
        return value
