import datetime
import logging
import os
import subprocess
import socketserver
import threading

import numpy as np
import pyshark

from http.server import BaseHTTPRequestHandler
from Kitsune import Kitsune

# Only 'yes' returns True
def environment_variable_to_bool(variable_name):
    if variable_name not in os.environ:
        return False
    return os.environ[variable_name] == 'yes'

NIDS = environment_variable_to_bool('NIDS')


class DenyList(object):
    def __init__(self):
        self.denied_ips = {}

    def deny_ip(self, ip_address):
        subprocess.run(['iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'REJECT'])
    
    def allow_ip(self, ip_address):
        subprocess.run(['iptables', '-D', 'INPUT', '-s', ip_address, '-j', 'REJECT'])

    def add_ip(self, ip, duration):
        denied_until_date = datetime.datetime.now() + datetime.timedelta(0, duration)
        self.deny_ip(ip)
        self.denied_ips[ip] = denied_until_date

    def remove_ip(self, ip):
        self.allow_ip(ip)
        del self.denied_ips[ip]

    def ip_to_be_removed(self, ip):
        now = datetime.datetime.now()
        denied_until_date = self.denied_ips[ip]
        if now > denied_until_date:
            self.remove_ip(ip)
            return True
        return False

    def retest_ip(self):
        for ip in self.denied_ips:
            self.ip_to_be_removed(ip)

    def is_ip_denied(self, ip):
        if ip in self.denied_ips:
            if self.ip_to_be_removed(ip):
                return False
            return True
        return False

class IntrusionDetectionSystem(object):
    def __init__(self, deny_list):
        self.deny_list = deny_list
        self.train_kitsune()

    def train_kitsune(self):
        logging.info("Training Kitsune")
        path = "/data/packets.pcap"  # the pcap, pcapng, or tsv file to process.
        packet_limit = 62000  # the number of packets to process
        # KitNET params:
        maxAE = 10  # maximum size for any autoencoder in the ensemble layer
        FMgrace = 15000  # the number of instances taken to learn the feature mapping (the ensemble's architecture)
        ADgrace = 46000  # the number of instances used to train the anomaly detector (ensemble itself)
        # Build Kitsune
        self.kitsune = Kitsune(path, packet_limit, maxAE, FMgrace, ADgrace)
        i = 0
        logging.info("Processing packets")
        while True:
            i += 1
            if i % 1000 == 0:
                logging.info(i)
            rmse = self.kitsune.proc_next_packet()
            if rmse == -1:
                break
        logging.info("Finished processing {} packet".format(i))       

    def packet_rmse(self, packet):
        return self.kitsune.process_packet(packet)

    def run(self):
        capture = pyshark.LiveCapture(interface='any', bpf_filter='tcp port 80', use_json=True, include_raw=True)
        for packet in capture.sniff_continuously():
            rmse = self.packet_rmse(packet)
            if rmse > 25.0:
                ip = packet['ip'].src_host
                ip_str = str(ip)
                logging.info("Note: {} with RMSE {}".format(ip_str, rmse))
                if rmse > 50.0:
                    logging.info("Denying {}".format(ip_str))
                    self.deny_list.add_ip(ip_str, 30)



class WebServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b'<html><head><title>Title</title></head><body>Test</body></html>')

    def log_message(self, format, *args):
        return


class ThreadedWebServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass


def run_intrusion_detection(deny_list):
    ids = IntrusionDetectionSystem(deny_list)
    logging.info("Starting up Intrusion Detection System")
    ids.run()


def run_webserver(deny_list):
    web_server = ThreadedWebServer(("0.0.0.0", 80), WebServer)
    web_server.deny_list = deny_list
    logging.info("Starting up web server")
    web_server.serve_forever()


def main():
    logging.basicConfig(format="%(asctime)s: %(message)s", datefmt="%H:%M:%S", level=logging.INFO)
    logging.info("Creating deny list")
    deny_list = DenyList()
    if NIDS:
        logging.info("Creating thread for Intrusion Detection System")
        ids_thread = threading.Thread(target=run_intrusion_detection, args=(deny_list,))
        logging.info("Starting thread for Intrusion Detection System")
        ids_thread.start()
    logging.info("Creating thread for web server")
    ws_thread = threading.Thread(target=run_webserver, args=(deny_list,))
    logging.info("Starting thread for web server")
    ws_thread.start()
    while True:
        deny_list.retest_ip


if __name__ == '__main__':
    main()
