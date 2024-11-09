import dictionary


def analyse():
    dictionary.ethernet_header = dictionary.pack_con[0:14]
    dictionary.ip_header = dictionary.pack_con[14:34]
    type_judge = dictionary.pack_con[23]
    if type_judge == '06':
        dictionary.tcp_header = dictionary.pack_con[34:54]
    elif type_judge == '11':
        dictionary.udp_header = dictionary.pack_con[34:42]

    dictionary.des_mac_addr = ':'.join(str(b) for b in dictionary.ethernet_header[0:6])
    dictionary.src_mac_addr = ':'.join(str(b) for b in dictionary.ethernet_header[6:12])
    dictionary.protocol_type = ':'.join(str(b) for b in dictionary.ethernet_header[12:14])
    dictionary.ip_version = ''
    if dictionary.ip_header[0] == '45':
        dictionary.ip_version = '4'
    else:
        dictionary.ip_version = '6'
    dictionary.ip_header_length = '20'

    dictionary.diff_service = dictionary.ip_header[1]
    dictionary.ip_total_length = str(int(dictionary.ip_header[2] + dictionary.ip_header[3], 16))
    dictionary.ip_identification = dictionary.ip_header[4] + dictionary.ip_header[5]
    dictionary.ip_flags = dictionary.ip_header[6]
    dictionary.ip_header_check_sum = "0x" + dictionary.ip_header[10] + dictionary.ip_header[11]
    dictionary.ip_alive_time = str(int(dictionary.ip_header[8], 16))
    if dictionary.ip_header[9] == "06":
        dictionary.ip_in_trans_protocol = "TCP"
    else:
        dictionary.ip_in_trans_protocol = "UDP"

    dictionary.ip_src_ip_adrr = '.'.join(str(int(con, 16)) for con in dictionary.ip_header[12:16])
    dictionary.ip_des_ip_adrr = '.'.join(str(int(con, 16)) for con in dictionary.ip_header[16:20])
    if dictionary.ip_in_trans_protocol == "TCP":
        dictionary.tcp_src_port = str(int(dictionary.tcp_header[0] + dictionary.tcp_header[1], 16))
        dictionary.tcp_des_port = str(int(dictionary.tcp_header[2] + dictionary.tcp_header[3], 16))
        dictionary.tcp_serial_num = str(
            int(dictionary.tcp_header[4] + dictionary.tcp_header[5] + dictionary.tcp_header[6] + dictionary.tcp_header[7],
                16))
        dictionary.tcp_ack_num = str(
            int(dictionary.tcp_header[8] + dictionary.tcp_header[9] + dictionary.tcp_header[10] + dictionary.tcp_header[11],
                16))

        bin_str = "{0:b}".format(int(dictionary.tcp_header[12] + dictionary.tcp_header[13]), 16)

        dictionary.tcp_header_length = str(int(bin_str[0:4], 2)) + bin_str[0:4]
        dictionary.tcp_reserved_segment = bin_str[4:10]

        dictionary.tcp_identification = bin_str[10:16]
        dictionary.tcp_window_size = str(int(dictionary.tcp_header[8] + dictionary.tcp_header[9], 16))
        dictionary.tcp_check_sum = "0x" + dictionary.tcp_header[10] + dictionary.tcp_header[11]
        dictionary.tcp_urg_pointer = dictionary.tcp_header[12] + dictionary.tcp_header[13]
        dictionary.tcp_opt_segment = ''


    elif dictionary.ip_in_trans_protocol == "UDP":
        dictionary.udp_src_port = str(int(dictionary.udp_header[0] + dictionary.udp_header[1], 16))
        dictionary.udp_des_port = str(int(dictionary.udp_header[2] + dictionary.udp_header[3], 16))
        dictionary.udp_length = str(int(dictionary.udp_header[4] + dictionary.udp_header[5], 16))
        dictionary.udp_check_sum = "0x" + dictionary.udp_header[6] + dictionary.udp_header[7]


def connect_info():
    ethernet_info = "-------------------------------帧信息-------------------------------\n" + "源MAC地址:" + dictionary.src_mac_addr + "\n目的MAC地址:" + dictionary.des_mac_addr + "\n协议类型:" + dictionary.protocol_type
    tcp_info = ""
    udp_info = ""
    type_judge = dictionary.pack_con[23]
    ip_info = "\n---------------------------- IP头部信息-----------------------------\n" + "IP头部长度:" + dictionary.ip_header_length + \
              "\nIP版本号:" + dictionary.ip_version + "\n区分服务: " + \
              dictionary.diff_service + "\nIP数据包总长度:" + dictionary.ip_total_length + "\n标识位:" + dictionary.ip_identification + \
              "\n标志:" + dictionary.ip_flags + "\n首部校验和:" + dictionary.ip_header_check_sum + "\n生存时间:" + dictionary.ip_alive_time + \
              "\n传输层协议:" + dictionary.ip_in_trans_protocol + "\n源IP地址:" + dictionary.ip_src_ip_adrr + "\n目的IP地址:" + dictionary.ip_des_ip_adrr

    if dictionary.ip_in_trans_protocol == "TCP":
        tcp_info = "\n----------------------------传输层协议信息--------------------------\n" + "协议类型: TCP\n" + \
                   "源端口号: " + dictionary.tcp_src_port + "\n目的端口号: " + dictionary.tcp_des_port + \
                   "\n序列号: " + dictionary.tcp_serial_num + "\n确认号: " + dictionary.tcp_ack_num + \
                   "\nTCP头部长: " + dictionary.tcp_header_length + "\n保留字段: " + dictionary.tcp_reserved_segment + \
                   "\n标志位: " + dictionary.tcp_identification + "\n窗口大小: " + dictionary.tcp_window_size + \
                   "\n校验和: " + dictionary.tcp_check_sum + "\n紧急指针: " + dictionary.tcp_urg_pointer + \
                   "\n选项字段: " + dictionary.tcp_opt_segment
        dictionary.trans_layer_protocl = tcp_info
    elif dictionary.ip_in_trans_protocol == "UDP":
        udp_info = "\n----------------------------传输层协议信息--------------------------\n" + "协议类型: UDP\n" + \
                   "源端口号: " + dictionary.udp_src_port + "\n目的端口号: " + dictionary.udp_des_port + "\n长度: " + dictionary.udp_length + \
                   "\nUDP校验和: " + dictionary.udp_check_sum
        dictionary.trans_layer_protocl = udp_info
    dictionary.analyse_info = ethernet_info + ip_info + dictionary.trans_layer_protocl
