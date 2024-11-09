checked_packet = ''
selected_packet = ''
which_partern = ''
scratch_data = []
network_card_info_list = []
header_info = []
wait = False
pack_con = []
stop = False
available = 10
dict = {}
dict_keys = []
scracth_countor = 0
des_context = ""

analyse_info = ""
cur_dir = ""
save_data_file_name = ''


ethernet_header = ""
des_mac_addr = ""
src_mac_addr = ""
protocol_type = ""
#ip
ip_header = ""
ip_version = ""
ip_header_length = ""
diff_service = ""
ip_total_length = ""
ip_identification = ""
ip_flags = ""
ip_header_check_sum = ""
ip_alive_time = ""
ip_in_trans_protocol = ""
ip_src_ip_adrr = ""
ip_des_ip_adrr = ""

trans_layer_protocl = ""
#tcp
tcp_info = ""
tcp_header = ""
tcp_src_port = ""
tcp_des_port = ""
tcp_serial_num = ""
tcp_ack_num = ""
tcp_header_length = ""
tcp_reserved_segment = ""
tcp_identification = ""
tcp_window_size = ""
tcp_check_sum = ""
tcp_urg_pointer = ""
tcp_opt_segment = ""

#udp
udp_header = ""
udp_src_port = ""
udp_des_port = ""
udp_length = ""
udp_check_sum = ""

