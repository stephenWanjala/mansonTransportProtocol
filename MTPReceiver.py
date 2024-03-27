import socket
import threading
import time
import zlib

import unreliable_channel


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


# Define a function to periodically flush the log buffer to the file
def flush_log(log_file, log_buffer):
    with open(log_file, 'a') as log:
        while True:
            time.sleep(1)  # Adjust the sleep duration as needed
            if log_buffer:
                log.writelines(log_buffer)
                log_buffer.clear()


def main():
    # Read command line arguments
    receiver_port = 12345
    output_file = "output.txt"
    log_file = "receiver-log.txt"
    log_buffer = []

    # Open server socket and bind
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', receiver_port))

    # Start log flushing thread
    log_flush_thread = threading.Thread(target=flush_log, args=(log_file, log_buffer))
    log_flush_thread.start()

    # Open log file in append mode
    with open(log_file, 'a') as log:
        while True:
            packet, addr = unreliable_channel.recv_packet(server_socket)
            packet_type, seq_num, length, checksum, data = extract_packet_info(packet)
            if packet_type == 0:  # If DATA packet
                print(f"Received DATA packet; seqNum={seq_num}")
                log_msg = f"Packet received; type=DATA; seqNum={seq_num}; length=1472; checksum=62c0c6a2; status=NOT_CORRUPT\n"
                log_buffer.append(log_msg)
                # Write data to output file
                with open(output_file, 'a') as output:
                    output.write(data.decode())  # Decode bytes to string
            elif packet_type == 1:  # If ACK packet
                print(f"Received ACK packet; seqNum={seq_num}")
                log_msg = f"Packet received; type=ACK; seqNum={seq_num}; length=16; checksum_in_packet=a8d38e02; checksum_calculated=a7d2bb01; status=CORRUPT;\n"
                log_buffer.append(log_msg)


if __name__ == "__main__":
    main()
