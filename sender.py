#!/usr/bin/python

import socket, sys, time, os, random, collections, time, copy
from socket import *
from ast import literal_eval as make_tuple


global seq
global ack
global flag
global r_ack
global r_seq
global sent_segments
global last_unacked
global start_time
global pDrop
global pDup
global pCorrupt
global corrupt
global pOrder
global pDelay
global reordered_packet
global reordered_count
global prev_ack
global delayed_packet

global total_bytes
global total_count
global pld_count
global drop_count
global corrupt_count
global rord_count
global delayed_count
global duplicated_count
global timeout_count
global fastrxt_count
global dupack_count


# OUTSIDE CODE
def checksum256(data):
    return reduce(lambda x,y:x+y, map(ord, data)) % 256

#<event> <time> <type-of-packet> <seq-number> <number-of-bytes-data><ack-number> 
def LOG_FILE(event,  typepacket, seq, nbytes, ack):
	fd = open("sender_log.txt", "ab+")

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

def CREATE_SEND_PACKET(source,dest,flag,data):
	global reordered_count
	global corrupt
	global total_count

	if data != "":
		checksum = checksum256(data)
	else: 
		checksum = 0

	if corrupt == True:
	# outside code https://stackoverflow.com/questions/10237926/convert-string-to-list-of-bits-and-viceversa
		bitlist = map(int, ''.join([bin(ord(i)).lstrip('0b').rjust(8,'0') for i in segmented_file[seq]]))

		bitcorrupt = random.randint(0, len(bitlist)-1)
		if bitlist[bitcorrupt] == 1:
			bitlist[bitcorrupt] = 0
		else:
			bitlist[bitcorrupt] = 1

		data = "".join(chr(int("".join(map(str,bitlist[i:i+8])),2)) for i in range(0,len(bitlist),8))	

		corrupt = False


	info = (flag,ack,seq ,data, checksum)
	packet = str(info)
	source.sendto(packet, dest)
	print "SENT    [", flag,ack,seq,"]"

	if (reordered_packet != ""):
		reordered_count += 1



def RECEIVE_UNPACK_PACKET(source):
	global flag
	global r_ack
	global r_seq
	global prev_ack

	data, server = source.recvfrom(1024)
	packet = make_tuple(data)

	flag = packet[0]
	r_ack  = packet[1]
	r_seq = packet[2]
	data = packet[3]
	print "RECEIVED[" ,packet[0], packet[1], packet[2], "]"


def UPDATE_ACK_SEQ(size_segment):
	global seq
	global ack
	seq += size_segment
	ack = 1


def UPDATE_timeout(time_out,estimatedRTT, gamma,devRTT):
	time_out = estimatedRTT + gamma * devRTT
	return time_out/1000

def UPDATE_estimatedRTT(estimatedRTT, sampleRTT):
	
	newEstimatedRTT = estimatedRTT *0.875 + 0.125*sampleRTT
	return	newEstimatedRTT

def UPDATE_devRTT(devRTT, estimatedRTT, sampleRTT):
	new_devRTT = 0.75*devRTT+0.75*abs(sampleRTT - estimatedRTT)
	return new_devRTT

################################################################################
# PLD MODULES
################################################################################

def PLDMODULE():
	global pld
	global total_count
	global pld_count
	global drop_count
	global corrupt_count
	global reordered_count
	global delayed_count
	global duplicated_count
	global timeout_count
	global fastrxt_count
	global dupack_count
	global rord_count

	pld_count += 1
	random_num = random.random()
	if random_num < pDrop:
		pld = "drop"
		drop_count +=1 
		return True

	random_num = random.random()
	if random_num < pDup:
		pld = "dup"
		duplicated_count += 1
		return True

	random_num = random.random()
	if random_num < pCorrupt:
		corrupt_count += 1
		pld = "corrupt"
		return True

	random_num = random.random()
	if random_num < pOrder:
		if reordered_packet == "":
			rord_count +=1 
			pld = "order"
			return True

	random_num = random.random()
	if random_num < pDelay:
		if delayed_packet == "":
			delayed_count +=1
			pld = "delay"
			return True


	return False




################################################################################
# initial set up
################################################################################


host_ip = sys.argv[1]
host_port = int(sys.argv[2])
file_name = str(sys.argv[3])
MWS = int(sys.argv[4])
MSS = int(sys.argv[5])
gamma = int(sys.argv[6])
pDrop = float(sys.argv[7])
pDup = float(sys.argv[8])
pCorrupt = float(sys.argv[9])
pOrder = float(sys.argv[10])
maxOrder = float(sys.argv[11])
pDelay  = float(sys.argv[12])
maxDelay = float(sys.argv[13])
seed = int(sys.argv[14])


####testing purposes  hardcoded
# host_ip = '127.0.0.1'
# host_port = 6777
# file_name = "test2.pdf"
# MWS = 500
# MSS = 50
# gamma = 4
# pDrop = 0.1
# pDup = 0.1
# pCorrupt = 0.1
# pOrder = 0.1
# maxOrder = 4
# pDelay = 0
# maxDelay = 0
# seed = 300

# ./sender.py 127.0.0.1 6777 test2.pdf 500 5000 4 0.1 0.1 0.1 0.1 4 0 0 300
#####################


host_info = (host_ip, host_port)
client_socket = socket(AF_INET, SOCK_DGRAM)
establish_connection = 0
seq = 0 
ack = 0
random.seed(seed)
start_time = time.time()*1000
reordered_packet = ""
delayed_packet = ""
corrupt = False

total_bytes = 0
total_count = 0
pld_count = 0
drop_count = 0
corrupt_count = 0
rord_count = 0
duplicated_count = 0 
delayed_count = 0
timeout_count = 0
fastrxt_count = 0
dupack_count = 0
rord_count = 0
################################################################################
# establishing connection
################################################################################

while establish_connection == 0:
	CREATE_SEND_PACKET(client_socket, host_info, "SYN", '')
	total_count += 1
	LOG_FILE("snd", "S", str(seq), "0", str(ack))
	packet = RECEIVE_UNPACK_PACKET(client_socket)
	if flag == "SYN-ACK":
			LOG_FILE("rcv", "SA", str(r_seq), "0", str(r_ack))
			seq = 1
			ack = 1
			CREATE_SEND_PACKET(client_socket, host_info, "ACK", '')
			total_count += 1
			LOG_FILE("snd", "A", str(seq), "0", str(ack))
			establish_connection = 1
			break

print " -----------Connection Established-------------"
################################################################################
# send file
################################################################################
print " -----------Preparing Data-------------"


fd = open(file_name, "rb")
bytes_left = os.path.getsize(file_name)
total_bytes = bytes_left
segmented_file = []

segmented_file = collections.OrderedDict()
seq = 1
while bytes_left != 0:
	if bytes_left - MSS > 0: 
		segmented_file[seq] = fd.read(MSS)
		seq += MSS
		bytes_left -= MSS
	else:
		segmented_file[seq] = fd.read(bytes_left)
		bytes_left -= bytes_left

fd.close()


print " -----------Sending Data-------------"


seq = 1
ack = 1
r_ack = 1
sent_segments = copy.deepcopy(segmented_file)
estimatedRTT = 500
devRTT = 250
time_out= UPDATE_timeout(0, estimatedRTT, gamma, devRTT)
packet_time = 0
smallest_unacked = 0
client_socket.setblocking(0)
pld = ""
#unacked_bytes = 0
reordered_packet = ""
reordered_count = 0
retransmit = False
finished = False
corrupt = False
#unacked_bytes = 0

fast_retransmit = 0

while True:


	#print sent_segments
	print "---- start loop----"
	print "waiting for ", smallest_unacked
	finish = False
	for seqnum, buff in sent_segments.items():
		if buff != 0:
			break
	if finished == True:
		break

	curr_time = time.time()*1000
	if(seq not in segmented_file):
		buffer_seq = seq
		seq = smallest_unacked
		retransmit = True
		seq = r_ack


	# print "window", #unacked_bytes
	# while (#unacked_bytes <= MWS):
	if (packet_time != 0 and curr_time-packet_time>time_out):	
		print "timed out"
		print "resending ", smallest_unacked
		timeout_count += 1
		buffer_seq = seq
		seq = smallest_unacked
		retransmit = True
		##unacked_bytes -= len(segmented_file[seq])

	elif (fast_retransmit >= 3):
		print "Fast retransmitting",prev_ack
		fastrxt_count =+ 1
		buffer_seq = seq
		seq = prev_ack
		retransmit = True
		fast_retransmit = 0
		

	elif (delayed_packet != "" and curr_time- delay_start > delay_time):
		print "sending ", delayed_packet , "delayed"

		if smallest_unacked == 0:
				smallest_unacked = delayed_packet

		buffer_seq = seq
		seq = delayed_packet
		CREATE_SEND_PACKET(client_socket, host_info, "ACK", segmented_file[delayed_packet])
		total_count += 1
		LOG_FILE("snd/dely", "D", str(seq), str(len(segmented_file[seq])), str(ack))
		#unacked_bytes += len(segmented_file[delayed_packet])
		seq = buffer_seq
		delayed_packet = ""

	elif (reordered_packet != "" and reordered_count > maxOrder):
		print "sending ", reordered_packet , "reordered"
		if smallest_unacked == 0:
				smallest_unacked = reordered_packet

		buffer_seq = seq
		seq = reordered_packet
		CREATE_SEND_PACKET(client_socket, host_info, "ACK", segmented_file[reordered_packet])
		total_count += 1
		LOG_FILE("snd/rord", "D", str(seq), str(len(segmented_file[seq])), str(ack))
		#unacked_bytes += len(segmented_file[reordered_packet])
		seq = buffer_seq

		reordered_count = 0
		reordered_packet = ""

	#in case packet is sent from above
	# if #unacked_bytes >= MWS :
	# 	print "window maxed", #unacked_bytes
	# 	break

	if (PLDMODULE() and seq in segmented_file):

		if pld == "drop":
			print " dropped ", seq ,"packet "

			if smallest_unacked == 0:
				smallest_unacked = seq
			if packet_time == 0:
				packet_time =  time.time()*1000
			temptime = time.time()*1000
			temptime = str(round(temptime - start_time, 3))
			LOG_FILE("drp", "D", str(seq), str(len(segmented_file[seq])), str(ack))
			#unacked_bytes += len(segmented_file[seq])
			UPDATE_ACK_SEQ(len(segmented_file[seq]))
			total_count += 1
			#unacked_bytes += len(segmented_file[seq])
			if (reordered_packet != ""):
				reordered_count += 1

		elif pld == "dup":
			print " packet ", seq  ,"duplicated "
			if smallest_unacked == 0:
				smallest_unacked = seq
			CREATE_SEND_PACKET(client_socket, host_info, "ACK", segmented_file[seq])
			CREATE_SEND_PACKET(client_socket, host_info, "ACK", segmented_file[seq])
			total_count += 1
			LOG_FILE("snd/dup", "D", str(seq), str(len(segmented_file[seq])), str(ack))
			#unacked_bytes += len(segmented_file[seq])
			UPDATE_ACK_SEQ(len(segmented_file[seq]))
			if packet_time == 0:
				packet_time =  time.time()*1000
	
		elif pld == "corrupt":
			print "packet ", seq, "corrupted"
				
			corrupt = True
			if smallest_unacked == 0:
				smallest_unacked = seq
			if packet_time == 0:
				packet_time =  time.time()*1000
			#======================================================================================
			
			CREATE_SEND_PACKET(client_socket, host_info, "ACK", segmented_file[seq])
			total_count += 1
			LOG_FILE("snd/corr", "D", str(seq), str(len(segmented_file[seq])), str(ack))
			#unacked_bytes += len(segmented_file[seq])
			UPDATE_ACK_SEQ(len(segmented_file[seq]))


		elif pld == "order":
			print "packet ", seq, "reordered"
			reordered_packet = seq
			reordered_count = 0
			rord_count += 1
			UPDATE_ACK_SEQ(len(segmented_file[seq]))

		elif pld == "delay":
			print "delayed ", seq, "packet"
			delayed_packet = seq
			delay_time = random.randint(0, maxDelay)
			delay_start = time.time()*1000
			UPDATE_ACK_SEQ(len(segmented_file[seq]))


	elif (seq in segmented_file): 
		
		if smallest_unacked == 0:
			smallest_unacked = seq
		if packet_time == 0:
			packet_time =  time.time()*1000
		CREATE_SEND_PACKET(client_socket, host_info, "ACK", segmented_file[seq])
		total_count += 1

		if retransmit == True:
			LOG_FILE("snd/RXT", "D", str(seq), str(len(segmented_file[seq])), str(ack))
		else:
			LOG_FILE("snd", "D", str(seq), str(len(segmented_file[seq])), str(ack))
		#unacked_bytes += len(segmented_file[seq])
		UPDATE_ACK_SEQ(len(segmented_file[seq]))

	if retransmit == True:
		seq = buffer_seq
		retransmit = False

	try:
		while True:
			
			 #-------------------------- check if send finished -----------------
			finished = True
			for seqnum, buff in sent_segments.items():
				if buff != 0:
					finished = False
					#smallest_unacked = seqnum
					break
			if finished == True:
				break
			prev_ack = r_ack
			RECEIVE_UNPACK_PACKET(client_socket)

			if sent_segments[r_seq] == 0:
				LOG_FILE("rcv/DA", "A", str(r_seq), "0", str(r_ack))
				dupack_count+=1
			else:
				LOG_FILE("rcv", "A", str(r_seq), "0", str(r_ack))
				#unacked_bytes += len(segmented_file[r_seq])

			if prev_ack == r_ack and sent_segments[r_ack] != 0:
				fast_retransmit += 1
			else:
				fast_retransmit = 1


			sent_segments[r_seq] = 0


			if r_seq == smallest_unacked:

				curr_time = time.time()*1000
				sampleRTT = curr_time - packet_time
				estimatedRTT =  UPDATE_estimatedRTT(estimatedRTT, sampleRTT)
				devRTT = UPDATE_devRTT(devRTT ,estimatedRTT, sampleRTT)
				time_out=UPDATE_timeout(time_out, estimatedRTT,gamma, devRTT)
				smallest_unacked = 0
				packet_time = 0
				print "updated time out", time_out	


	except Exception as e:
		continue

		

print "ACKED PACKETS: ", sent_segments

print " -----------Data Sent-------------"

################################################################################
# closing connection
################################################################################
print " -----------Closing Connection-------------"

CREATE_SEND_PACKET(client_socket, host_info, "FIN", '')
total_count += 1 
LOG_FILE("snd", "F", str(seq), "0", str(ack))
client_socket.setblocking(1)

while establish_connection == 1:
	flag = 0 #zero out flag from prev	
	RECEIVE_UNPACK_PACKET(client_socket)
	LOG_FILE("rcv", "A", str(r_seq), "0", str(r_ack))
	while establish_connection == 1:
		RECEIVE_UNPACK_PACKET(client_socket)
		if flag == "FIN":
			LOG_FILE("rcv", "F", str(r_seq), "0", str(r_ack))
			CREATE_SEND_PACKET(client_socket, host_info, "ACK", '')
			total_count += 1
			LOG_FILE("snd", "A", str(seq), "0", str(ack))
			establish_connection = 0
		

	

print " -----------Connection Closed-------------"
client_socket.close()


fd = open("sender_log.txt", "ab+")

fd.write("File size sent: "+ str(total_bytes)+"\n")
fd.write("Segments transmitted: "+str(total_count)+"\n")
fd.write("Segments handled by PLD:"+ str(pld_count)+"\n")
fd.write("Segments dropped:"+ str(drop_count)+"\n")
fd.write("Segments corrupted:"+ str(corrupt_count)+"\n")
fd.write("Segments reordered:"+ str(rord_count)+"\n")
fd.write("Segments delayed:"+ str(delayed_count)+"\n")
fd.write("Segments duplicated:"+ str(duplicated_count)+"\n")
fd.write("Retransmission due to TIMEOUT:"+ str(timeout_count)+"\n")
fd.write("Retransmission due to FAST RETRANSMIT:"+ str(fastrxt_count)+"\n")
fd.write("Duplicate Acks: "+ str(dupack_count)+"\n")


