## The code provided here is just a skeleton that can help you get started
## You can add/remove functions as you wish


## import (add more if you need)
import threading
import unreliable_channel


## define and initialize
# window_size, window_base, next_seq_number, dup_ack_count, etc.
# client_port


## we will need a lock to protect against concurrent threads
lock = threading.Lock()


def create_packet(..):
# Two types of packets, data and ack
# crc32 available through zlib library


def extract_packet_info(..):
# extract the packet data after receiving


def receive_thread(..):
	while True:
		# receive packet, but using our unreliable channel
		# packet_from_server, server_addr = unreliable_channel.recv_packet(socket)
		# call extract_packet_info
		# check for corruption, take steps accordingly
		# update window size, timer, triple dup acks


def main(..):
	# read the command line arguments

	# open log file and start logging

	# open client socket and bind

	# start receive thread
	recv_thread = threading.Thread(target=rec_thread,args=(client_socket,))
	recv_thread.start()

	# take the input file and split it into packets (use create_packet)

	# while there are packets to send:
		# send packets to server using our unreliable_channel.send_packet() 

		# update the window size, timer, etc.

