import math
import os

PADDING = 26

successful_connections = {}
failed_connections = {}

def main():
    directory_content = os.listdir('docker_data')
    files = filter(lambda f: os.path.isfile('docker_data/' + f), directory_content)
    for file in files:
        with open('docker_data/' + file, 'r') as handler:
            global successful_connections
            global failed_connections
            client_type = int(handler.readline())
            success = int(handler.readline())
            if client_type in successful_connections:
                successful_connections[client_type] += success
            else:
                successful_connections[client_type] = success
            failed = int(handler.readline())
            if client_type in failed_connections:
                failed_connections[client_type] += failed
            else:
                failed_connections[client_type] = failed

    header_1 = pad('Client type', PADDING)
    header_2 = pad('Successful connections', PADDING)
    header_3 = pad('Failed connections', PADDING)
    print("\n{}|{}|{}".format(header_1, header_2, header_3))
    for i in range(0, 4):
        print('-'*(PADDING * 3 + 2))
        print("{}|{}|{}".format(
            pad(i, PADDING),
            pad('Not present' if i not in successful_connections else successful_connections[i], PADDING),
            pad('Not present' if i not in failed_connections else failed_connections[i], PADDING)))
    print("\n")

def pad(input, padding, prepad = 2):
    input_str = str(input)
    remaining_length = max(0, padding - (len(input_str) + prepad))   
    return ' ' * prepad + input_str + ' ' * remaining_length

if __name__ == '__main__':
    main()
