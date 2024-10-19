"""
resolve3.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

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
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": name})
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
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


def lookup(target_name: dns.name.Name,
           qtype: dns.rdatatype) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.
    Parameters: target_name the hostname to get a DNS record for
                qtype the type of DNS record that is being looked for
    """
    # Resources:
    #   Message class for dnspython: https://dnspython.readthedocs.io/en/stable/message-class.html
    #   DNS Record info: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12
    #   DNS RFC: https://www.ietf.org/rfc/rfc1035.txt
    ''' use command 'dig +trace {{target_name}} +nodnssec' to see an example route to a target_name  '''

    verbose = True

    if verbose:
        print("\n\n##################### Resolve ", dns.rdatatype.RdataType(qtype).name, " for: ", target_name, " ###################")

    # Check cache to check for target_name and return result if it does (if it's a CNAME then call lookup)
    if target_name.labels in answer_cache.keys():
        if qtype in answer_cache[target_name.labels].keys():  # If found exact match then return answer
            if verbose:
                print("Found cached answer")
            return answer_cache[target_name.labels][qtype]
        elif dns.rdatatype.CNAME in answer_cache[target_name.labels].keys():
            if len(answer_cache[target_name.labels][dns.rdatatype.CNAME].answer) > 0:
                if verbose:
                    print("Found cached alias")
                # If CNAME cache then call unaliased lookup
                return lookup((answer_cache[target_name.labels][dns.rdatatype.CNAME]).answer[0][0].target, qtype)

    '''
    Initialize servers_to_query with root_servers
    create servers_to_query
    Check cache for domain authority
    If found, make the most local domain authority the next server to query
    '''
    servers_to_query = []
    # TODO authority map. look at whether it returns the string i can map it to. otherwise manually calculate authority hostname: #########################################
    # TODO: If the domain from the below for loop is in the answer cache then query that domain for the answer

    for i in reversed(range(len(target_name.labels)-2)):
        domain = target_name.labels[i+1:]
        if domain in authority_cache.keys():
            if len(authority_cache[domain][dns.rdatatype.A]) > 0:
                for server in authority_cache[domain][dns.rdatatype.A]:
                    servers_to_query.append((dns.rdatatype.A, server))
            # else:
            #     for server in authority_cache[domain][dns.rdatatype.CNAME]:
            #         servers_to_query.append((dns.rdatatype.CNAME, server))
            if verbose:
                print("FOUND CACHED NAMESPACE AUTHORITY FOR ", str(domain))
        if domain in answer_cache.keys():
            if verbose:
                print("FOUND CACHED NAMESPACE ANSWER FOR ", str(domain))
            if dns.rdatatype.A in answer_cache[domain].keys():
                servers_to_query.append((dns.rdatatype.A, answer_cache[domain][dns.rdatatype.A]))
            # elif dns.rdatatype.CNAME in answer_cache[domain].keys():
            #     servers_to_query.append((dns.rdatatype.CNAME, answer_cache[domain][dns.rdatatype.CNAME]))
    if len(servers_to_query) == 0:
        xdsafdsfds = ""
        for server in ROOT_SERVERS:
            servers_to_query.append((dns.rdatatype.A, server))

    queried_servers = []

    while len(servers_to_query):
        server_entry = servers_to_query.pop()
        server = server_entry[1]

        if server_entry[0] == dns.rdatatype.CNAME:
            if target_name not in active_lookups and target_name.labels != server_entry[1].labels:
                if verbose:
                    print("CALL TO ", target_name, " RESOLVING SERVER TO QUERY ", server, )

                active_lookups.add(target_name)
                server_ip = lookup(server, dns.rdatatype.A)
                active_lookups.discard(target_name)
                if len(server_ip.answer):
                    server = str(server_ip.answer[0][0])
                else:
                    continue
            else: # skip current server
                continue

        if server in queried_servers:
            continue
        queried_servers.append(server)

        if verbose:
            print("\nQuerying: ", server)

        try:
            outbound_query = dns.message.make_query(target_name, qtype)
            response = dns.query.udp(outbound_query, server, 3)
        except Exception as e:
            if verbose:
                print("Failed to reach server")
            continue

        if len(response.answer):
            if verbose:
                print("Answer Found: ", response.answer)

            if target_name.labels not in answer_cache.keys():
                answer_cache[target_name.labels] = {}
            answer_cache[target_name.labels][response.answer[0].rdtype] = response
            if response.answer[0].rdtype == qtype:
                return response
            elif response.answer[0].rdtype == dns.rdatatype.CNAME:
                active_lookups.add(target_name)
                res = lookup(response.answer[0][0].target, qtype)
                active_lookups.discard(target_name)
                return res
            else:
                if verbose:
                    print("Found answer but couldn't use it :(")
        elif len(response.authority): # Response gave no answers but did give authorities to look towards
            if verbose:
                print("Authorities found: ", response.authority)
                if len(response.additional):
                    print("ADDITIONAL FOUND: ", response.additional)
            for authority_list in response.authority:
                if authority_list.rdtype == dns.rdatatype.NS:  # We only support NS authorities
                    if authority_list.name not in authority_cache.keys():  # Any NS we come across should get an empty record created
                        authority_cache[authority_list.name.labels] = {dns.rdatatype.CNAME: [], dns.rdatatype.A: [], dns.rdatatype.AAAA: [], dns.rdatatype.MX: []}
                    for server_name in authority_list:
                        # Cache all authority CNAMEs even if there's no answer
                        if server_name.target.labels not in authority_cache[authority_list.name.labels][dns.rdatatype.CNAME]:
                            authority_cache[authority_list.name.labels][dns.rdatatype.CNAME].append(server_name.target.labels)

                        foundMap = False
                        for server_RR in response.additional:
                            if server_RR.rdtype == dns.rdatatype.A:
                                if server_name.target.labels not in authority_cache.keys():
                                    authority_cache[server_name.target.labels] = {dns.rdatatype.CNAME: [], dns.rdatatype.A: [], dns.rdatatype.AAAA: [], dns.rdatatype.MX: []}
                                if server_RR[0] not in authority_cache[server_name.target.labels][dns.rdatatype.A]:
                                    authority_cache[server_name.target.labels][dns.rdatatype.A].append(str(server_RR[0]))
                                if server_RR.name == server_name.target:
                                    servers_to_query.append((dns.rdatatype.A, str(server_RR[0]), server_name.target))
                                    foundMap = True
                                    break
                        if not foundMap:
                            if server_name.target.labels in authority_cache.keys():
                                if dns.rdatatype.A in authority_cache[server_name.target.labels]:
                                    for server in authority_cache[server_name.target.labels][dns.rdatatype.A]:
                                        servers_to_query.append((dns.rdatatype.A, server, str(server_name)))
                            else:
                                servers_to_query.append((dns.rdatatype.CNAME, server_name.target, str(server_name)))
        else:
            if verbose:
                print("Query returned no results")
        # Just continue onto next server in servers_to_query

    if verbose:
        print("Ran out of servers to query")
    # Cache the fact that this route doesn't resolve to anything.
    if target_name.labels not in answer_cache.keys():
        answer_cache[target_name.labels] = {}
    answer_cache[target_name.labels][qtype] = dns.message.Message()
    return dns.message.Message()


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

