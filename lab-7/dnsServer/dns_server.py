'''DNS Server for Content Delivery Network (CDN)
'''

import sys
from socketserver import UDPServer, BaseRequestHandler
from utils.dns_utils import DNS_Request, DNS_Rcode
from utils.ip_utils import IP_Utils
from datetime import datetime
import math

import re
from collections import namedtuple

import copy
import random

__all__ = ["DNSServer", "DNSHandler"]


class DNSServer(UDPServer):
    def __init__(self, server_address, dns_file, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate=True)
        self._dns_table = {}
        self.parse_dns_file(dns_file)
        
    def parse_dns_file(self, dns_file):
        # ---------------------------------------------------
        # TODO: your codes here. Parse the dns_table.txt file
        # and load the data into self._dns_table.
        # --------------------------------------------------
        with open('dnsServer/dns_table.txt', 'r') as reader:
            while True:
                line = reader.readline()
                if not line:
                    break
                else:
                    table_info = line.split()
                    self._dns_table[table_info[0]] = copy.deepcopy(table_info)


    @property
    def table(self):
        return self._dns_table


class DNSHandler(BaseRequestHandler):
    """
    This class receives clients' udp packet with socket handler and request data. 
    ----------------------------------------------------------------------------
    There are several objects you need to mention:
    - udp_data : the payload of udp protocol.
    - socket: connection handler to send or receive message with the client.
    - client_ip: the client's ip (ip source address).
    - client_port: the client's udp port (udp source port).
    - DNS_Request: a dns protocl tool class.
    We have written the skeleton of the dns server, all you need to do is to select
    the best response ip based on user's infomation (i.e., location).

    NOTE: This module is a very simple version of dns server, called global load ba-
          lance dns server. We suppose that this server knows all the ip addresses of 
          cache servers for any given domain_name (or cname).
    """
    
    def __init__(self, request, client_address, server):
        self.table = server.table
        super().__init__(request, client_address, server)
        # test server table
        # with open('testDNS_output.txt', 'w') as writer:
        #     for key, values in self.table.items():
        #         writer.write(key)
        #         writer.write(" -> ")
        #         for value in values:
        #             writer.write(f"{value} ")
        #         writer.write("\n")

    def calc_distance(self, pointA, pointB):
        ''' TODO: calculate distance between two points '''
        x = abs(pointA[0] - pointB[0])
        y = abs(pointA[1] - pointB[1])
        x = math.pow(x, 2)
        y = math.pow(y, 2)
        res = math.sqrt(x + y)
        return res

    def get_response(self, request_domain_name):
        response_type, response_val = (None, None)
        # ------------------------------------------------
        # TODO: your codes here.
        # Determine an IP to response according to the client's IP address.
        #       set "response_ip" to "the best IP address".
        client_ip, _ = self.client_address
        # match *, such as 
        # request_domain_name = test.cncourse.org. 
        # server_table_domain_name = *.cncourse.org.
        regex_flag = 1
        if (request_domain_name in self.table):
            regex_flag = 0
        if (regex_flag):
            for key in self.table.keys():
                if "*" in key:
                    key = key[1:]
                    if (re.search(key, request_domain_name) is not None):
                        request_domain_name = "*" + key
        if (request_domain_name in self.table):
            if (self.table[request_domain_name][1] == "CNAME"):
                response_type = "CNAME"
                response_val = self.table[request_domain_name][2]
            elif (self.table[request_domain_name][1] == "A"):
                response_type = "A"
                # only one record in the list
                table_len = len(self.table[request_domain_name])
                min_distant = 0x3f3f3f3f
                if (table_len == 3):
                    response_val = self.table[request_domain_name][2]
                else:
                    # need to adopt a random load balance policy for multiple servers
                    if (IP_Utils.getIpLocation(client_ip) is None):
                        random_load_flag = random.randint(2, table_len - 1)
                        response_val = self.table[request_domain_name][random_load_flag]
                    # need to select the nearest Cache Node
                    else:
                        client_ip_location = IP_Utils.getIpLocation(client_ip)
                        i = 2
                        min_distant_flag = 0
                        while (i < table_len):
                            server_ip_location = IP_Utils.getIpLocation(self.table[request_domain_name][i])
                            if (server_ip_location is not None):
                                res = self.calc_distance(server_ip_location, client_ip_location)
                                if (res < min_distant):
                                    min_distant = res
                                    min_distant_flag = i
                            i += 1
                        if min_distant_flag == 0:
                            response_val = None
                        else:
                            response_val = self.table[request_domain_name][min_distant_flag]
        # -------------------------------------------------

        # test result
        # with open('testDNS_output.txt', 'w') as writer:
        #     writer.write(f"request_domain_name: {request_domain_name}\n")
        #     writer.write(f"response_type: {response_type}\n")
        #     writer.write(f"response_value: {response_val}\n")
        #     writer.write(f"response_value: {self.table[request_domain_name][2]}\n")
        #     writer.write(f"distant: {min_distant}\n")

        return (response_type, response_val)


    def handle(self):
        """
        This function is called once there is a dns request.
        """
        ## init udp data and socket.
        udp_data, socket = self.request

        ## read client-side ip address and udp port.
        client_ip, client_port = self.client_address

        ## check dns format.
        valid = DNS_Request.check_valid_format(udp_data)
        if valid:
            ## decode request into dns object and read domain_name property.
            dns_request = DNS_Request(udp_data)
            request_domain_name = str(dns_request.domain_name)
            self.log_info(f"Receving DNS request from '{client_ip}' asking for "
                          f"'{request_domain_name}'")

            # get caching server address
            response = self.get_response(request_domain_name)

            # response to client with response_ip
            if None not in response:
                dns_response = dns_request.generate_response(response)
            else:
                dns_response = DNS_Request.generate_error_response(
                                             error_code=DNS_Rcode.NXDomain)
        else:
            self.log_error(f"Receiving invalid dns request from "
                           f"'{client_ip}:{client_port}'")
            dns_response = DNS_Request.generate_error_response(
                                         error_code=DNS_Rcode.FormErr)

        socket.sendto(dns_response.raw_data, self.client_address)

    def log_info(self, msg):
        self._logMsg("Info", msg)

    def log_error(self, msg):
        self._logMsg("Error", msg)

    def log_warning(self, msg):
        self._logMsg("Warning", msg)

    def _logMsg(self, info, msg):
        ''' Log an arbitrary message.
        Used by log_info, log_warning, log_error.
        '''
        info = f"[{info}]"
        now = datetime.now().strftime("%Y/%m/%d-%H:%M:%S")
        sys.stdout.write(f"{now}| {info} {msg}\n")
