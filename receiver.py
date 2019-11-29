#!/usr/bin/python

import socket, sys, time, os, time
from socket import *
from ast import literal_eval as make_tuple

global flag
global ack
global seq
global data
global client
global checksum
global skip_packet
global r_ack
global r_seq

global total_size
global total_segments
global data_segments
global total_corrupt
global dupack_recv
global dupack_sent

# OUTSIDE CODE
def checksum256(data):
    return reduce(lambda x,y:x+y, map(ord, data)) % 256

def CREATE_SEND_PACKET(source,dest,flag,data):
	info = (flag,ack,seq,data)
	packet = str(info)
	source.sendto(packet, dest)
	print "SENT    [", flag,ack,seq,"]"


def RECEIVE_UNPACK_PACKET(source, size):
	global client
	global flag
	global r_ack
	global r_seq
	global data
	global checksum
	global skip_packet
	global total_segments

	total_segments +=1
	skip_packet = False

	info, client = source.recvfrom(4029)
	packet = make_tuple(info)
	flag = packet[0]
	r_ack  = packet[1]
	r_seq = packet[2]
	data = packet[3]
	checksum = packet[4]
	print "RECEIVED[" ,packet[0], packet[1], packet[2], "]"

	if data != "":
		calc_checksum = checksum256(data)
		if calc_checksum != checksum:
			print "corrupt packet", r_seq
			skip_packet = True


def LOG_FILE(event,  typepacket, seq, nbytes, ack):
	fd = open("receiver_log.txt", "ab+")

	temptime = time.time()*1000
	temptime = str(temptime - start_time)

	line = event
	line += "        " + temptime
	line += "        " + typepacket
	line += "        " + seq
	line += "        " + nbytes
	line += "        " + ack
	fd.write(line)
	fd.write("\n")


################################################################################
# initial set up
################################################################################
# setting up destination info

host_port = int(sys.argv[1])
file_name = str(sys.argv[2])

# ./receiver 6777 testpdd.pdf



MSS = 1000
host_ip = '127.0.0.1'

host_info = (host_ip, host_port)
server_socket = socket(AF_INET, SOCK_DGRAM)
server_socket.bind(host_info)
establish_connection = 0
segmented_file = {}
largest_ack = 0
start_time = time.time()*1000

total_size = 0
total_segments = 0
data_segments = 0
total_corrupt = 0
dupack_recv = 0
dupack_sent = 0

print " --------------------------------------------------------------------------------------------------------"
while True:

################################################################################
# establishing connection
################################################################################
	while establish_connection == 0:
 		
		RECEIVE_UNPACK_PACKET(server_socket, MSS) 
		ack = r_ack
		seq = r_seq
		if flag == "SYN":
			LOG_FILE("rcv",  "S", str(r_seq), "0", str(r_ack))
			CREATE_SEND_PACKET(server_socket, client, "SYN-ACK", '')
			LOG_FILE("snd",  "SA", str(seq), "0", str(ack))
		if flag == "ACK":
			LOG_FILE("rcv",  "A", str(r_seq), "0", str(ack))
			establish_connection = 1
			expected_packet = 1
			print " -----------Connection Established-------------"



################################################################################
# receive connection
################################################################################
	print " -----------Receiving Data-------------"

	print "expecting ", expected_packet
	
	RECEIVE_UNPACK_PACKET(server_socket, MSS)



################################################################################
# close connection
################################################################################		
	if flag == "FIN":
		LOG_FILE("rcv",  "F", str(r_seq), "0", str(r_ack))
		print " -----------Saving Data-------------"
		fd = open(file_name, "ab+")
		sorted_segments = sorted(segmented_file.keys(), key=lambda x: int(x))

		for key in sorted_segments:
			fd.write(segmented_file[key])
			
		fd.close()
		print sorted_segments

		print " -----------Closing Connection-------------"
		
		while establish_connection == 1:
			CREATE_SEND_PACKET(server_socket, client, "ACK",  '')
			LOG_FILE("snd",  "A", str(seq), "0", str(ack))
			CREATE_SEND_PACKET(server_socket, client, "FIN", '')
			LOG_FILE("snd",  "F", str(seq), "0", str(ack))
			while establish_connection == 1:
				RECEIVE_UNPACK_PACKET(server_socket, MSS)
				if flag == "ACK":
					LOG_FILE("rcv",  "A", str(r_seq), "0", str(r_ack))
					print " -----------Connection Closed-------------"
					establish_connection = 0
					server_socket.close()

					fd = open("receiver_log.txt", "ab+")

					fd.write("Total data : "+ str(total_size)+"\n")
					fd.write("Total segments : "+ str(total_segments)+"\n")
					fd.write("Data segments:  "+ str(data_segments)+"\n")
					fd.write("Corrupt segments "+ str(total_corrupt)+"\n")
					fd.write("Duplicate segments received "+ str(dupack_recv)+"\n")
					fd.write("Duplicate ACKS sent "+ str(dupack_sent)+"\n")
					exit()


################################################################################
# recieve file
################################################################################
	#if packet not corrupt
	if skip_packet == False:
		data_segments += 1
		total_size += len(data)
		if str(r_seq) not in segmented_file:
			LOG_FILE("rcv",  "D", str(r_seq), str(len(data)), str(r_ack))

		else:
			LOG_FILE("rcv/DA",  "D", str(r_seq), str(len(data)), str(r_ack))
			dupack_recv += 1

		segmented_file[str(r_seq)] = data

		if r_seq == expected_packet:
			ack = len(data) + r_seq
			while True:
				if str(ack) not in segmented_file.keys():
					print ack
					break
				else:
					 ack+= len(data)

			seq = expected_packet

			CREATE_SEND_PACKET(server_socket, client, "ACK",  '')
			LOG_FILE("snd",  "A", str(seq), "0", str(ack))
			expected_packet = ack

		elif r_seq != expected_packet:
			print "requesting", expected_packet
			seq = r_seq	
			ack = expected_packet
			CREATE_SEND_PACKET(server_socket, client, "ACK",  '')
			LOG_FILE("snd/DA",  "A", str(seq), "0", str(ack))
			dupack_sent +=1 

	else:
		LOG_FILE("rcv/corr",  "D", str(r_seq), str(len(data)), str(r_ack))
		total_size += len(data)
		total_corrupt =+ 1



