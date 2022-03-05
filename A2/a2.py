import statistics
import packet_struct
import sys

GLOBAL_HEADER_SIZE = 24
PACKET_HEADER_SIZE = 16
ETHERNET_HEADER_SIZE = 14
LITTLE_ENDIAN = "<"
BIG_ENDIAN = ">"


def get_endianness(file_bytes):
    """
    Checks the global header to determine the endianness
    :param file_bytes:
    :return: The endianness to be used to unpack the file
    """
    if file_bytes[:2] == b"\xa1\xb2":
        endianness = BIG_ENDIAN
    elif file_bytes[:2] == b"\xd4\xc3":
        endianness = LITTLE_ENDIAN
    return endianness


def parse(file_bytes, endianness):
    """
    Parses the file and extracts the content into packet objects
    :param file_bytes: The provided file
    :param endianness: The endianness to use while unpacking the file
    :return: A list of all the packet objects
    """
    packets = []
    orig_time = None
    packet_number = 1
    while file_bytes:
        packet_obj = packet_struct.packet()

        packet_header = file_bytes[:16]

        if not orig_time:
            packet_obj.timestamp_set(packet_header[0:4], packet_header[4:8], 0, endianness)
            orig_time = packet_obj.timestamp

        packet_obj.packet_No = packet_number
        packet_obj.timestamp_set(packet_header[0:4], packet_header[4:8], orig_time, endianness)
        packet_obj.incl_len_set(packet_header[8:12], endianness)
        incl_len = packet_obj.packet_incl_len

        packet_data = file_bytes[PACKET_HEADER_SIZE:PACKET_HEADER_SIZE + incl_len]

        ip_header_obj = packet_struct.IP_Header()
        ip_header_obj.get_header_len(packet_data[ETHERNET_HEADER_SIZE:ETHERNET_HEADER_SIZE + 1])
        ip_header_length = ip_header_obj.ip_header_len

        ip_header = packet_data[ETHERNET_HEADER_SIZE:ETHERNET_HEADER_SIZE + ip_header_length]
        ip_header_obj.get_total_len(ip_header[2:4])
        ip_header_obj.get_IP(ip_header[12:16], ip_header[16:20])

        tcp_header_and_payload = packet_data[ETHERNET_HEADER_SIZE + ip_header_length:incl_len]

        tcp_header_obj = packet_struct.TCP_Header()
        tcp_header_obj.get_src_port(tcp_header_and_payload[:2])
        tcp_header_obj.get_dst_port(tcp_header_and_payload[2:4])
        tcp_header_obj.get_seq_num(tcp_header_and_payload[4:8])
        tcp_header_obj.get_ack_num(tcp_header_and_payload[8:12])
        tcp_header_obj.get_data_offset(tcp_header_and_payload[12:13])
        tcp_header_obj.get_flags(tcp_header_and_payload[13:14])
        tcp_header_obj.get_window_size(tcp_header_and_payload[14:15], tcp_header_and_payload[15:16])

        packet_obj.IP_header = ip_header_obj
        packet_obj.TCP_header = tcp_header_obj
        packets.append(packet_obj)

        file_bytes = file_bytes[PACKET_HEADER_SIZE + incl_len:]
        packet_number += 1
    return packets


def group_by_connection(packets):
    """
    Groups all packets into connections defined by the src_ip, dst_ip, src_port, dst_port 4-tuple
    :param packets: The list of packets to group into connections
    :return: A dictionary with keys being the 4-tuple defining the connection and the values being the packets of that
    connection
    """
    connection_dic = {}
    for packet in packets:
        key1 = (
            packet.IP_header.src_ip, packet.IP_header.dst_ip, packet.TCP_header.src_port, packet.TCP_header.dst_port)
        key2 = (
            packet.IP_header.dst_ip, packet.IP_header.src_ip, packet.TCP_header.dst_port, packet.TCP_header.src_port)
        if key1 in connection_dic:
            connection_dic[key1].append(packet)
        elif key2 in connection_dic:
            connection_dic[key2].append(packet)
        else:
            connection_dic[key1] = [packet]
    return connection_dic


def get_connection_objects(connection_dic):
    """
    Creates a connection object for each connection as well as prints the details for each individual connection
    :param connection_dic: A dictionary with keys being the 4-tuple defining the connection and the values being the
    packets of that connection
    :return: connection_objects: A list of connection objects which hold general information about the connection
            rtt: A list of all the RTT times
    """
    connection_objects = []
    rtt = []
    for index, connection in enumerate(connection_dic.values(), 1):
        print("Connection {}:".format(index))

        source = connection[0].IP_header.src_ip
        print("\tSource Address: {}".format(source))
        print("\tDestination Address: {}".format(connection[0].IP_header.dst_ip))
        print("\tSource Port: {}".format(connection[0].TCP_header.src_port))
        print("\tDestination Port: {}".format(connection[0].TCP_header.dst_port))

        connection_obj = packet_struct.Connection()
        SYN_counter = 0
        FIN_counter = 0
        start = None
        end = None
        bytes_sent = 0
        bytes_received = 0
        for packet in connection:
            if packet.IP_header.src_ip == source:
                connection_obj.packets_sent += 1
                bytes_sent += packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset
            else:
                connection_obj.packets_received += 1
                bytes_received += packet.IP_header.total_len - packet.IP_header.ip_header_len - packet.TCP_header.data_offset

            connection_obj.window_size.append(packet.TCP_header.window_size)

            flags_dict = packet.TCP_header.flags
            if flags_dict["RST"]:
                connection_obj.reset = True
            if flags_dict["SYN"]:
                if not start:
                    start = packet.timestamp
                SYN_counter += 1
            if flags_dict["FIN"]:
                FIN_counter += 1
                connection_obj.complete = True

        print("\tStatus: S{}F{}{}".format(SYN_counter, FIN_counter, "/R" if connection_obj.reset else ""))

        if connection_obj.complete:
            for packet in reversed(connection):
                flags_dict = packet.TCP_header.flags
                if flags_dict["FIN"]:
                    end = packet.timestamp
                    break
            connection_obj.duration = end - start

            print("\tStart Time: {} seconds".format(round(start, 5)))
            print("\tEnd Time: {} seconds".format(round(end, 5)))
            print("\tDuration: {} seconds".format(round(connection_obj.duration, 2)))
            print("\tNumber of packets sent from Source to Destination: {}".format(connection_obj.packets_sent))
            print("\tNumber of packets sent from Destination to Source: {}".format(connection_obj.packets_received))
            print("\tTotal number of packets: {}".format(connection_obj.packets_sent + connection_obj.packets_received))
            print("\tNumber of data bytes sent from Source to Destination: {}".format(bytes_sent))
            print("\tNumber of data bytes sent from Destination to Source: {}".format(bytes_received))
            print("\tTotal number of data bytes: {}".format(bytes_sent + bytes_received))
        print("-" * 80)

        connection_objects.append(connection_obj)

        # Calculating rtt values
        find_ack_dic = {}
        if connection_obj.complete:
            for ind, packet in enumerate(connection):
                if packet.IP_header.src_ip == source:
                    if not (packet.TCP_header.flags['SYN'] == 0 and packet.TCP_header.flags['ACK'] == 1 and
                            packet.TCP_header.flags['RST'] == 0 and packet.TCP_header.flags['FIN'] == 0):
                        if packet.TCP_header.flags['SYN'] == 1 or packet.TCP_header.flags['FIN'] == 1:
                            find_ack_dic[packet.TCP_header.seq_num + 1] = packet
                        else:
                            find_ack_dic[
                                packet.TCP_header.seq_num + packet.packet_incl_len - packet.TCP_header.data_offset - packet.IP_header.ip_header_len - ETHERNET_HEADER_SIZE] = packet
                if packet.TCP_header.ack_num in find_ack_dic.keys() and packet.IP_header.src_ip != source:
                    prev_packet = find_ack_dic[packet.TCP_header.ack_num]
                    prev_packet.get_RTT_value(packet)
                    rtt.append(prev_packet.RTT_value)
                    del find_ack_dic[packet.TCP_header.ack_num]
    return connection_objects, rtt


def main():
    """
    Takes a TCP trace file and parses and analyzes it
    """
    if len(sys.argv) < 2:
        print("No input given")
        print("Exiting gracefully")
        sys.exit()

    tcp_file = sys.argv[1]

    f = open(tcp_file, "rb")

    file_bytes = f.read()

    endianness = get_endianness(file_bytes)

    # Remove global header from file_bytes
    file_bytes = file_bytes[GLOBAL_HEADER_SIZE:]

    packets = parse(file_bytes, endianness)

    connection_dic = group_by_connection(packets)

    print("A) Total number of connections: {}".format(len(connection_dic)))
    print("-"*80)

    print("B) Connection's details")
    connection_objects, rtt = get_connection_objects(connection_dic)

    # Analyze connections
    complete_connections = 0
    reset_connections = 0
    time_duration = []
    packets = []
    window_size = []
    for connection_obj in connection_objects:
        if connection_obj.complete:
            complete_connections += 1
            time_duration.append(connection_obj.duration)
            packets.append(connection_obj.packets_sent + connection_obj.packets_received)
            window_size += connection_obj.window_size
        if connection_obj.reset:
            reset_connections += 1

    print("C) General")
    print("Total number of complete TCP connections: {}".format(complete_connections))
    print("Number of reset TCP connections: {}".format(reset_connections))
    print("Number of TCP connections that were still open when the trace capture ended: {}"
          .format(len(connection_dic) - complete_connections))
    print("-"*80)

    print("D) Complete TCP connections")
    print("Minimum time duration: {} seconds".format(round(min(time_duration), 2)))
    print("Mean time duration: {} seconds".format(round(statistics.mean(time_duration), 2)))
    print("Maximum time duration: {} seconds".format(round(max(time_duration), 2)))

    print("Minimum RTT value: {} seconds".format(round(min(rtt), 6)))
    print("Mean RTT value: {} seconds".format(round(statistics.mean(rtt), 6)))
    print("Maximum RTT value: {} seconds".format(round(max(rtt), 6)))

    print("Minimum number of packets including both send/received: {}".format(min(packets)))
    print("Mean number of packets including both send/received: {}".format(round(statistics.mean(packets), 2)))
    print("Maximum number of packets including both send/received: {}".format(max(packets)))

    print("Minimum receive window size including both send/received: {}".format(min(window_size)))
    print("Mean receive window size including both send/received: {}".format(round(statistics.mean(window_size), 2)))
    print("Maximum receive window size including both send/received: {}".format(max(window_size)))
    print("-"*80)


if __name__ == '__main__':
    main()
