import time

class rebulid_pkt:
    def __init__(self, pkt, subnet, port, targetip):
        self.packet = pkt
        self.recent_time = time.time()
        self.num_of_retries = 0
        self.match_subnet = subnet
        self.send_out_port = port
        self.targetipaddress = targetip

    def try_to_send(self):
        self.num_of_retries = self.num_of_retries + 1

    def update_time(self):
        self.recent_time = time.time()

    def get_num_of_retries(self):
        return self.num_of_retries

    def get_recent_time(self):
        return self.recent_time

    def get_targetipaddress(self):
        return self.targetipaddress

    def get_send_out_port(self):
        return self.send_out_port

    def get_packet(self):
        return self.packet

    def get_subnet(self):
        return self.match_subnet