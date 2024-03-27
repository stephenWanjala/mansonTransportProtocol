import socket
import threading
import time
import zlib

import unreliable_channel

lock = threading.Lock()


def create_packet(packet_type, seq_num, data):
    length = len(data)
    checksum = zlib.crc32(
        packet_type.to_bytes(4, 'big') + seq_num.to_bytes(4, 'big') + length.to_bytes(4, 'big') + data)
    return packet_type.to_bytes(4, 'big') + seq_num.to_bytes(4, 'big') + length.to_bytes(4, 'big') + checksum.to_bytes(
        4, 'big') + data


def extract_packet_info(packet):
    packet_type = int.from_bytes(packet[0:4], 'big')
    seq_num = int.from_bytes(packet[4:8], 'big')
    length = int.from_bytes(packet[8:12], 'big')
    checksum = int.from_bytes(packet[12:16], 'big')
    data = packet[16:]
    return packet_type, seq_num, length, checksum, data


def receive_thread(socket):
    while True:
        packet, addr = unreliable_channel.recv_packet(socket)
        packet_type, seq_num, length, checksum, data = extract_packet_info(packet)
        if packet_type == 1:  # If ACK packet
            print(f"Received ACK; seqNum={seq_num}")
            # Implement ACK handling
            pass


# Define a function to periodically flush the log buffer to the file
def flush_log(log_file, log_buffer):
    with open(log_file, 'a') as log:
        while True:
            time.sleep(1)  # Adjust the sleep duration as needed
            if log_buffer:
                log.writelines(log_buffer)
                log.flush()  # Flush the buffer to update the log file
                log_buffer.clear()


def main():
    # Read command line arguments
    receiver_ip = "127.0.0.1"  # For testing on localhost
    receiver_port = 12345
    window_size = 10
    input_file = "1MB.txt"
    log_file = "sender-log.txt"
    log_buffer = []

    # Open client socket and bind
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.bind(('0.0.0.0', 0))

    # Start receive thread
    recv_thread = threading.Thread(target=receive_thread, args=(client_socket,))
    recv_thread.start()

    # Start the log flushing thread
    log_flush_thread = threading.Thread(target=flush_log, args=(log_file, log_buffer))
    log_flush_thread.start()

    # Read input file and split into packets
    with open(input_file, 'r') as file:
        lines = file.readlines()

    try:
        # Start sender logic
        window_base = 0
        next_seq_number = 0
        while window_base < len(lines):
            lock.acquire()
            while next_seq_number < window_base + window_size and next_seq_number < len(lines):
                packet = create_packet(0, next_seq_number, lines[next_seq_number].encode())  # Encode to bytes
                unreliable_channel.send_packet(client_socket, packet, (receiver_ip, receiver_port))
                log_msg = f"Packet sent; type=DATA; seqNum={next_seq_number}; length=1472; checksum=62c0c6a2\n"
                print(log_msg)
                log_buffer.append(log_msg)
                next_seq_number += 1
            lock.release()
            time.sleep(0.01)  # Adjust sleep time as needed
    except Exception as e:
        print(f"Error writing to log file: {e}")


if __name__ == "__main__":
    main()
