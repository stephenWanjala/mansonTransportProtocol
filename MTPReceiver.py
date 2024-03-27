## The code provided here is just a skeleton that can help you get started
## You can add/remove functions as you wish

## import (add more if you need)
import unreliable_channel

def create_packet(..):
# Two types of packets, data and ack
# crc32 available through zlib library


def extract_packet_info(..):
# extract the packet data after receiving


def main(..):
	# read the command line arguments

	# open log file and start logging

	# open server socket and bind

	while True:
		# receive packet, but using our unreliable channel
		# packet_from_server, server_addr = unreliable_channel.recv_packet(socket)
		# call extract_packet_info
		# check for corruption and lost packets, send ack accordingly


