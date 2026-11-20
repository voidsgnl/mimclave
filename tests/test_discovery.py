from mimclave.discovery.ports import parse_proc_net_table

TCP_FIXTURE = """  sl  local_address rem_address   st
   0: 0100007F:1F90 00000000:0000 0A
   1: 0100007F:0035 00000000:0000 01
"""


def test_parse_proc_tcp_only_returns_listeners() -> None:
    found = parse_proc_net_table(TCP_FIXTURE, "ipv4", "tcp")
    assert len(found) == 1
    assert found[0].address == "127.0.0.1"
    assert found[0].port == 8080
    assert found[0].transport == "tcp"


def test_parse_proc_ipv6_listener() -> None:
    fixture = """ sl local_address rem_address st
0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A
"""
    found = parse_proc_net_table(fixture, "ipv6", "tcp")
    assert found[0].address == "::"
    assert found[0].port == 22


def test_parse_proc_udp_bound_socket() -> None:
    fixture = """ sl local_address rem_address st
0: 0100007F:0035 00000000:0000 07
"""
    found = parse_proc_net_table(fixture, "ipv4", "udp")
    assert found[0].port == 53
