"""
resolve3.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
from dns import rdatatype

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

# current as of 19 October 2020
ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, rdatatype.CNAME)
    cnames = []
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": name})
    # lookup A
    response = lookup(target_name, rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response


answer_cache = {}
authority_cache = {}
active_lookups = set()


def load_initial_servers_to_query(target_name: dns.name.Name):
    """
    This function finds any intermediate NS Authority caches for the given name
    and return the list of results ordered from least significant
    to most significant
    """
    servers_to_query = []
    # Search for caches of intermediate namespaces
    for i in reversed(range(len(target_name.labels) - 2)):
        domain = target_name.labels[i + 1:]
        if domain in authority_cache:
            for server in authority_cache[domain]:
                servers_to_query.append((rdatatype.CNAME, server))
        if domain in answer_cache:
            if rdatatype.A in answer_cache[domain].keys():
                servers_to_query.append(
                    (rdatatype.A, answer_cache[domain][rdatatype.A])
                )
            elif rdatatype.CNAME in answer_cache[domain].keys():
                servers_to_query.append(
                    (rdatatype.CNAME, answer_cache[domain][rdatatype.CNAME])
                )
    if len(servers_to_query) == 0:
        for server in ROOT_SERVERS:
            servers_to_query.append((rdatatype.A, server))
    return servers_to_query


def do_dns_query(target_name: dns.name.Name,
                 outbound_query: dns.message.QueryMessage,
                 server: str,
                 servers_to_query: list):
    """
    Executes a DNS query then caches the answers, authorities,
    and additional info while adding any new authorities to the
    servers_to_query list

    target_name: The name of the target being queried for
    outbound_qeury: The DNS query to execute
    server: The server to query for an answer
    servers_to_query: A list of servers in the format (rdtype, name)
    """
    try:
        response = dns.query.udp(outbound_query, server, 3)

        # Map answers from answer to answer_cache
        if target_name.labels not in answer_cache:
            answer_cache[target_name.labels] = {}
        for answer_rr in response.answer:
            answer_cache[target_name.labels][answer_rr.rdtype] = answer_rr
        # Map answers from additional to answer_cache
        for server_rr in response.additional:
            if server_rr.name.labels not in answer_cache:
                answer_cache[server_rr.name.labels] = {}
            answer_cache[server_rr.name.labels][server_rr.rdtype] = server_rr
        # Map NS records from authority to authority_cache
        # Record authorities as next servers to query
        for ns_record in response.authority:
            if ns_record.rdtype == rdatatype.NS and len(ns_record) > 0:
                authority_cache[ns_record.name.labels] = []
                for authority_name in ns_record:
                    authority_cache[ns_record.name.labels].append(
                        authority_name.target
                    )
                    servers_to_query.append(
                        (rdatatype.CNAME, authority_name.target)
                    )
    except dns.exception.Timeout:
        pass
    except ValueError:
        pass


def resolve_dns_cname(server: dns.name.Name) -> str:
    """
    Takes a server name and resolves it to it's A record or returns ""

    server: the name of the server
    """
    # Don't query if looked up at a lower program depth
    if server not in active_lookups:
        if server in answer_cache and rdatatype.A in answer_cache[server]:
            return answer_cache[server][rdatatype.A][0]

        # Otherwise call a lookup for it
        active_lookups.add(server)
        server_ip = lookup(server, rdatatype.A)
        active_lookups.discard(server)
        if len(server_ip.answer) > 0:
            return str(server_ip.answer[0][0])
    return ""


def lookup(target_name: dns.name.Name,
           qtype: rdatatype) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.
    Parameters: target_name the hostname to get a DNS record for
                qtype the type of DNS record that is being looked for
    """
    outbound_query = dns.message.make_query(target_name, qtype)
    servers_to_query = load_initial_servers_to_query(target_name)
    queried_servers = []

    while len(servers_to_query) > 0:
        # Check if an answer is cached
        if target_name.labels in answer_cache:
            if qtype in answer_cache[target_name.labels]:
                response = dns.message.make_response(outbound_query)
                if len(answer_cache[target_name.labels][qtype]) > 0:
                    response.answer = [answer_cache[target_name.labels][qtype]]
                return response
            if (
                rdatatype.CNAME in answer_cache[target_name.labels].keys()
                and len(answer_cache[target_name.labels][rdatatype.CNAME]) > 0
            ):
                active_lookups.add(target_name)
                res = lookup(
                  answer_cache[target_name.labels][rdatatype.CNAME][0].target,
                  qtype
                )
                active_lookups.discard(target_name)
                return res

        # Load next server to query
        server_entry = servers_to_query.pop()
        server = server_entry[1]

        # If CNAME record being queried then we need to find its address
        if server_entry[0] == rdatatype.CNAME:
            server = resolve_dns_cname(server)
            if server == "":
                continue

        if server in queried_servers:
            continue
        queried_servers.append(server)

        do_dns_query(target_name, outbound_query, server, servers_to_query)
        # End of loop
    # Cache the fact that this route doesn't resolve to anything.
    if target_name.labels not in answer_cache:
        answer_cache[target_name.labels] = {}
    answer_cache[target_name.labels][qtype] = []
    return dns.message.make_response(outbound_query)


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))


if __name__ == "__main__":
    main()
