#!/usr/bin/env python3
"""Generate a tiny MaxMind DB fixture for wardd's GeoIP tests.

The GeoIP-dependent tests need a real MMDB. Shipping a third-party country
database would bring its own licensing and would be several hundred kilobytes
of binary in the tree, so this writes a synthetic one instead: a handful of
documentation-range prefixes tagged with invented country codes. It is
dependency-free (standard library only) and deterministic, so it can run at
configure time on any host.

Format reference: MaxMind DB File Format Specification, version 2.0.

Usage: make_test_mmdb.py <output.mmdb>
"""
import ipaddress
import struct
import sys

RECORD_SIZE = 32          # bits per record; 4 bytes, big-endian
NODE_BYTES = RECORD_SIZE * 2 // 8
METADATA_MARKER = b"\xab\xcd\xefMaxMind.com"

# Country assignments. IPv4 is stored under ::/96 so that libmaxminddb's
# ipv4_start_node walk (96 zero bits) finds it, matching real v6 databases.
# wardd requires a country to have both IPv4 and IPv6 prefixes, and requires
# that it never covers a default route.
NETWORKS = [
    ("192.0.2.0/25",      "CN"),   # TEST-NET-1, lower half
    ("198.18.0.0/15",     "CN"),   # benchmarking range
    ("203.0.113.0/24",    "JP"),   # TEST-NET-3
    ("2001:db8:1::/48",   "CN"),   # documentation range
    ("2001:db8:2::/48",   "JP"),
]


def encode_control(type_number, size):
    """Control byte, optional extended-type byte, then any size bytes."""
    if type_number < 8:
        tag, extended = type_number, b""
    else:
        tag, extended = 0, bytes([type_number - 7])
    if size < 29:
        head = bytes([(tag << 5) | size])
        trailer = b""
    elif size < 285:
        head = bytes([(tag << 5) | 29])
        trailer = bytes([size - 29])
    elif size < 65821:
        head = bytes([(tag << 5) | 30])
        trailer = (size - 285).to_bytes(2, "big")
    else:
        head = bytes([(tag << 5) | 31])
        trailer = (size - 65821).to_bytes(3, "big")
    return head + extended + trailer


def encode_string(value):
    raw = value.encode("utf-8")
    return encode_control(2, len(raw)) + raw


def encode_unsigned(type_number, value, width):
    raw = value.to_bytes(width, "big").lstrip(b"\x00")
    return encode_control(type_number, len(raw)) + raw


def encode_map(pairs):
    out = encode_control(7, len(pairs))
    for key, value in pairs:
        out += encode_string(key) + value
    return out


def encode_array(items):
    return encode_control(11, len(items)) + b"".join(items)


class Trie:
    """Binary search tree over 128-bit keys, as the MMDB format defines it."""

    def __init__(self):
        self.children = [None, None]      # Trie, or ("data", country)

    def insert(self, network, country):
        node = self
        bits = int.from_bytes(network.network_address.packed, "big")
        for depth in range(network.prefixlen):
            bit = (bits >> (127 - depth)) & 1
            last = depth == network.prefixlen - 1
            if last:
                if node.children[bit] is not None:
                    raise SystemExit("overlapping fixture network: %s" % network)
                node.children[bit] = ("data", country)
            else:
                if node.children[bit] is None:
                    node.children[bit] = Trie()
                elif not isinstance(node.children[bit], Trie):
                    raise SystemExit("fixture network splits a leaf: %s" % network)
                node = node.children[bit]


def build(path):
    root = Trie()
    for text, country in NETWORKS:
        network = ipaddress.ip_network(text)
        if network.version == 4:
            # Map into ::/96, the IPv4 subtree of a v6 database.
            mapped = ipaddress.ip_network(
                "::%s/%d" % (network.network_address, network.prefixlen + 96)
            )
        else:
            mapped = network
        root.insert(mapped, country)

    # Depth-first index assignment over internal nodes only.
    order = []

    def collect(node):
        order.append(node)
        for child in node.children:
            if isinstance(child, Trie):
                collect(child)

    collect(root)
    index_of = {id(node): position for position, node in enumerate(order)}
    node_count = len(order)

    # Data section: one record per distinct country.
    data_section = bytearray()
    data_offset = {}
    for country in sorted({country for _, country in NETWORKS}):
        data_offset[country] = len(data_section)
        data_section += encode_map(
            [("country", encode_map([("iso_code", encode_string(country))]))]
        )

    def record_value(child):
        if child is None:
            return node_count                                  # empty
        if isinstance(child, Trie):
            return index_of[id(child)]                         # next node
        return node_count + 16 + data_offset[child[1]]         # data pointer

    tree = bytearray()
    for node in order:
        for child in node.children:
            value = record_value(child)
            if value >= 1 << RECORD_SIZE:
                raise SystemExit("record value exceeds the record size")
            tree += struct.pack(">I", value)
    assert len(tree) == node_count * NODE_BYTES

    metadata = encode_map([
        ("binary_format_major_version", encode_unsigned(5, 2, 2)),
        ("binary_format_minor_version", encode_unsigned(5, 0, 2)),
        ("build_epoch", encode_unsigned(9, 1767225600, 8)),   # fixed: reproducible
        ("database_type", encode_string("wardd-test-Country")),
        ("description", encode_map([("en", encode_string("wardd synthetic test fixture"))])),
        ("ip_version", encode_unsigned(5, 6, 2)),
        ("languages", encode_array([encode_string("en")])),
        ("node_count", encode_unsigned(6, node_count, 4)),
        ("record_size", encode_unsigned(5, RECORD_SIZE, 2)),
    ])

    with open(path, "wb") as handle:
        handle.write(bytes(tree))
        handle.write(b"\x00" * 16)          # data section separator
        handle.write(bytes(data_section))
        handle.write(METADATA_MARKER)
        handle.write(bytes(metadata))

    return node_count, len(data_section)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    nodes, data_bytes = build(sys.argv[1])
    print("wrote %s: %d nodes, %d data bytes" % (sys.argv[1], nodes, data_bytes))
