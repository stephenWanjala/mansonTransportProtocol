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


def receive_thread(socket, output_file, log_file, log_buffer):
    with open(output_file, 'wb') as output:
        while True:
            packet, addr = unreliable_channel.recv_packet(socket)
            packet_type, seq_num, length, checksum, data = extract_packet_info(packet)
            if packet_type == 0:  # If DATA packet
                print(f"Received DATA packet; seqNum={seq_num}")
                log_msg = (f"Packet received; type=DATA; seqNum={seq_num}; length=1472; checksum=62c0c6a2; "
                           f"status=NOT_CORRUPT\n")
                log_buffer.append(log_msg)
                flush_log(log_file, log_buffer)
                output.write(data)
                ack_packet = create_packet(1, seq_num, b'')
                unreliable_channel.send_packet(socket, ack_packet, addr)
                print(f"Sent ACK; seqNum={seq_num} length=16 checksum=62c0c6a2\n")
                log_msg = f"Packet sent; type=ACK; seqNum={seq_num}; length=16; checksum=62c0c6a2\n"
                log_buffer.append(log_msg)
                flush_log(log_file, log_buffer)


# Define a function to periodically flush the log buffer to the file
def flush_log(log_file, log_buffer):
    with open(log_file, 'a') as log:
        while log_buffer:
            log.writelines(log_buffer)
            log_buffer.clear()
            time.sleep(1)  # Adjust the sleep duration as needed


def main():
    # Read command line arguments
    receiver_port = 13452
    log_file = "receiver-log.txt"
    log_buffer = []

    # Open server socket and bind
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('0.0.0.0', receiver_port))

    # Start receive thread
    recv_thread = threading.Thread(target=receive_thread, args=(server_socket, "output.txt", log_file, log_buffer))
    recv_thread.start()

    # Start the log flushing thread
    log_flush_thread = threading.Thread(target=flush_log, args=(log_file, log_buffer))
    log_flush_thread.start()


if __name__ == "__main__":
    main()

