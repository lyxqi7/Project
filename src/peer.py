import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
import select
import util.simsocket as simsocket
import struct
import socket
import util.bt_utils as bt_utils
import hashlib
import argparse
import pickle

"""
This is CS305 project skeleton code.
Please refer to the example files - example/dumpreceiver.py and example/dumpsender.py - to learn how to play with this skeleton.
"""

BUF_SIZE = 1400
CHUNK_DATA_SIZE = 512 * 1024  # 512 kb
HEADER_LEN = struct.calcsize("HBBHHII")

config = None
ex_output_file = None
ex_received_chunk = dict()
ex_sending_chunkhash = dict()
ex_downloading_chunkhash = ""
MAX_PAYLOAD = 1024
timer = dict()



def process_download(sock, chunkfile, outputfile):
    '''
        if DOWNLOAD is used, the peer will keep getting files until it is done
        '''
    print('PROCESS GET SKELETON CODE CALLED.  Fill me in! I\'ve been doing! (', chunkfile, ',     ', outputfile, ')')
    global ex_output_file
    global ex_received_chunk
    global ex_downloading_chunkhash

    ex_output_file = outputfile
    # Step 1: read chunkhash to be downloaded from chunkfile
    download_hash = bytes()
    with open(chunkfile, 'r') as cf:
        lines = cf.readlines()
        for line in lines:
            index, datahash_str = line.strip().split(" ")
            ex_received_chunk[datahash_str] = bytes()
            ex_downloading_chunkhash = datahash_str

            # hex_str to bytes
            datahash = bytes.fromhex(datahash_str)
            download_hash = download_hash + datahash

    # Step2: make WHOHAS pkt
    # |2byte magic|1byte team |1byte type|
    # |2byte  header len |2byte pkt len  |
    # |      4byte  seq                  |
    # |      4byte  ack                  |
    whohas_header = struct.pack("HBBHHII", socket.htons(52305), 44, 0, socket.htons(HEADER_LEN),
                                socket.htons(HEADER_LEN + len(download_hash)), socket.htonl(0), socket.htonl(0))
    whohas_pkt = whohas_header + download_hash  # 谁有含这些hash的chunk

    # Step3: flooding whohas to all peers in peer list
    peer_list = config.peers
    for p in peer_list:
        if int(p[0]) != config.identity:
            sock.sendto(whohas_pkt, (p[1], int(p[2])))


def process_inbound_udp(sock):
    # Receive pkt
    global config
    global timer

    global ex_sending_chunkhash
    pkt, from_addr = sock.recvfrom(BUF_SIZE)
    magic_raw, Team, Type, hlen_raw, plen_raw, Seq_raw, Ack_raw = struct.unpack("HBBHHII", pkt[:HEADER_LEN])
    data = pkt[HEADER_LEN:]
    if Type == 0:
        # received an WHOHAS pkt
        # see what chunk the sender has
        whohas_chunk_hash = data[:socket.ntohs(plen_raw) - HEADER_LEN]
        # bytes to hex_str
        what_I_have = bytes()
        Send_IHAVE = False
        num = 0

        for i in range(len(whohas_chunk_hash) // 20):
            chunkhash_str = bytes.hex(whohas_chunk_hash[20 * i:20 * i + 20])
            if chunkhash_str in config.haschunks:
                Send_IHAVE = True
                what_I_have = what_I_have + whohas_chunk_hash[20 * i:20 * i + 20]
                ex_sending_chunkhash[num] = chunkhash_str
                num += 1

        print(f"whohas: {bytes.hex(what_I_have)}, has: {list(config.haschunks.keys())}")
        if Send_IHAVE:
            # send back IHAVE pkt
            ihave_header = struct.pack("HBBHHII", socket.htons(52305), 44, 1, socket.htons(HEADER_LEN),
                                       socket.htons(HEADER_LEN + len(what_I_have)), socket.htonl(0),
                                       socket.htonl(0))
            ihave_pkt = ihave_header + what_I_have
            sock.sendto(ihave_pkt, from_addr)
    elif Type == 1:
        # received an IHAVE pkt
        # see what chunk the sender has
        whohas_chunk_hash = data[:socket.ntohs(plen_raw) - HEADER_LEN]

        for i in range(len(whohas_chunk_hash) // 20):
            get_chunk_hash = data[20 * i:20 * i + 20]

            # send back GET pkt
            get_header = struct.pack("HBBHHII", socket.htons(52305), 44, 2, socket.htons(HEADER_LEN),
                                     socket.htons(HEADER_LEN + len(get_chunk_hash)), socket.htonl(0), socket.htonl(0))
            get_pkt = get_header + get_chunk_hash
            sock.sendto(get_pkt, from_addr)
    elif Type == 2:
        # received a GET pkt
        chunk_data = config.haschunks[bytes.hex(data[:20])][:MAX_PAYLOAD]

        # send back DATA
        data_header = struct.pack("HBBHHII", socket.htons(52305), 44, 3, socket.htons(HEADER_LEN),
                                  socket.htons(HEADER_LEN+len(chunk_data)), socket.htonl(1), 0)
        timer[str(from_addr) + str(1)] = [time.time(), from_addr, data_header + chunk_data]  # 给data包一个定时器
        sock.sendto(data_header + chunk_data, from_addr)
    elif Type == 3:
        # received a DATA pkt
        ex_received_chunk[ex_downloading_chunkhash] += data

        # send back ACK
        ack_pkt = struct.pack("HBBHHII", socket.htons(52305), 44, 4, socket.htons(HEADER_LEN), socket.htons(HEADER_LEN),
                              0, Seq_raw)

        sock.sendto(ack_pkt, from_addr)

        # see if finished
        if len(ex_received_chunk[ex_downloading_chunkhash]) == CHUNK_DATA_SIZE:
            # finished downloading this chunkdata!
            # dump your received chunk to file in dict form using pickle
            with open(ex_output_file, "wb") as wf:
                pickle.dump(ex_received_chunk, wf)

            # add to this peer's haschunk:
            config.haschunks[ex_downloading_chunkhash] = ex_received_chunk[ex_downloading_chunkhash]

            # you need to print "GOT" when finished downloading all chunks in a DOWNLOAD file
            print(f"GOT {ex_output_file}")

            # The following things are just for illustration, you do not need to print out in your design.
            sha1 = hashlib.sha1()
            sha1.update(ex_received_chunk[ex_downloading_chunkhash])
            received_chunkhash_str = sha1.hexdigest()
            print(f"Expected chunkhash: {ex_downloading_chunkhash}")
            print(f"Received chunkhash: {received_chunkhash_str}")
            success = ex_downloading_chunkhash == received_chunkhash_str
            print(f"Successful received: {success}")
            if success:
                print("Congrats! You have completed the example!")
            else:
                print("Example fails. Please check the example files carefully.")
    elif Type == 4:
        # received an ACK pkt
        ack_num = socket.ntohl(Ack_raw)
        del timer[str(from_addr) + str(ack_num)]

        if (ack_num) * MAX_PAYLOAD >= CHUNK_DATA_SIZE:
            # finished
            print(f"finished sending {ex_sending_chunkhash}")
            pass
        else:
            left = (ack_num) * MAX_PAYLOAD
            right = min((ack_num + 1) * MAX_PAYLOAD
                        , CHUNK_DATA_SIZE)
            next_data = config.haschunks[ex_sending_chunkhash[0]][left: right]
            # send next data
            data_header = struct.pack("HBBHHII", socket.htons(52305), 44, 3, socket.htons(HEADER_LEN),
                                      socket.htons(HEADER_LEN + len(next_data)), socket.htonl(ack_num + 1), 0)
            sock.sendto(data_header + next_data, from_addr)

            timer[str(from_addr) + str(ack_num + 1)] = [time.time(), from_addr, data_header + next_data]  # 给data包一个定时器


def process_user_input(sock):
    command, chunkf, outf = input().split(' ')
    if command == 'DOWNLOAD':
        process_download(sock, chunkf, outf)
    else:
        pass


def peer_run(config):
    addr = (config.ip, config.port)
    sock = simsocket.SimSocket(config.identity, addr, verbose=config.verbose)

    try:
        while True:
            ready = select.select([sock, sys.stdin], [], [], 0.1)
            read_ready = ready[0]


            if len(read_ready) > 0:
                if sock in read_ready:
                    process_inbound_udp(sock)
                if sys.stdin in read_ready:
                    process_user_input(sock)
            else:
                # No pkt nor input arrives during this period 
                for i in timer.keys():  # 超时重传
                    if time.time() - timer[i][0] > config.timeout:
                        sock.sendto(timer[i][2], timer[i][1])
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()


if __name__ == '__main__':
    """
    -p: Peer list file, it will be in the form "*.map" like nodes.map.
    -c: Chunkfile, a dictionary dumped by pickle. It will be loaded automatically in bt_utils. The loaded dictionary has the form: {chunkhash: chunkdata}
    -m: The max number of peer that you can send chunk to concurrently. If more peers ask you for chunks, you should reply "DENIED"
    -i: ID, it is the index in nodes.map
    -v: verbose level for printing logs to stdout, 0 for no verbose, 1 for WARNING level, 2 for INFO, 3 for DEBUG.
    -t: pre-defined timeout. If it is not set, you should estimate timeout via RTT. If it is set, you should not change this time out.
        The timeout will be set when running test scripts. PLEASE do not change timeout if it set.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', type=str, help='<peerfile>     The list of all peers', default='nodes.map')
    parser.add_argument('-c', type=str, help='<chunkfile>    Pickle dumped dictionary {chunkhash: chunkdata}')
    parser.add_argument('-m', type=int, help='<maxconn>      Max # of concurrent sending')
    parser.add_argument('-i', type=int, help='<identity>     Which peer # am I?')
    parser.add_argument('-v', type=int, help='verbose level', default=0)
    parser.add_argument('-t', type=int, help="pre-defined timeout", default=3)
    args = parser.parse_args()

    config = bt_utils.BtConfig(args)
    peer_run(config)
