# tcp-simulator
Brief:
	My version of STP uses a tuple as the packet containing all the header fields and the data. This is sent from the sender to the receiver as a string, which is then converted back into a tuple on the receiver side. Both the sender and receiver keeps track of the local ack and sequence number (this is the value the local program expects to use), and received ack and received sequence (value used as a request from the other side for a specific packet). The local and received values are used so that if a segment is interrupted either due to a timeout/fast retransmit, the program will know where to start sending again. 

	The sender and receiver uses socket blocking (turned off) to overcome the stop and wait implementation. The sender will continuously send packets until a response is received from the receiver. A dictionary is used on both sender and receiver to save the segments according to their sequence numbers.

There is a bug (unknown causes) which causes the sender to not receive the acknowledgement packets fast enough causing it’s own unstable packet delay from the receiver end.

Features:

Sender:
-	Three way handshake to establish connection
-	Four segment connection termination
-	Send segmented file even in situations created by the PLD
-	Handles packet timeouts based on timeout intervals
o	Timeout intervals updated every time a packet is sent/correct ack is received
-	File segments sent based on MSS 
-	MWS was not implemented
-	PLD:
o	Dropped packets
o	Duplicate packets
o	Corrupted packets
o	Reordered packets
	Bug with 
o	Delayed packets (simplified)
	Only allows for 1 packet to be delayed at a time (similar to re-order)

Receiver:
-	Three way handshake to establish connection
-	Four segment connection termination
-	Handles out of order packets
-	Handles corrupted packets accordingly
-	Requests correct packets from the sender which are needed (ie, for fast retransmit)
-	Does not have a dynamic range to receive from socket (static number of bytes to read from socket)
