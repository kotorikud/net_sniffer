import tkinter as tk
import threading
import time
from winpcapy import WinPcapUtils
import dictionary
import network_card
import analyze
import capture

def begin_capture():
    capture_thread = threading.Thread(target=capture.start)
    capture_thread.setDaemon(True)
    capture_thread.start()

def end_capture():
    WinPcapUtils.stop

class NetworkSnifferGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.configure_window()
        self.setup_menu()
        self.setup_widgets()
        self.refresh_thread = threading.Thread(target=self.periodic_refresh)
        self.refresh_thread.setDaemon(True)
        self.refresh_thread.start()

    def configure_window(self):
        self.root.geometry('1100x600+200+30')
        self.root.resizable(False, False)
        self.root.title('Network Sniffer')

    def setup_menu(self):
        menu = tk.Menu(self.root)
        menu.add_command(label="  Select Network Card  ", command=network_card.get_network_card_info)
        menu.add_command(label="  Start Capture  ", command=begin_capture)
        menu.add_command(label="  Stop Capture  ", command=end_capture)
        self.root.config(menu=menu)
    
    def setup_widgets(self):
        self.packet_list_frame = tk.LabelFrame(self.root, text="Packet List", width=600, height=500, relief='groove', bd=2)
        self.binary_frame = tk.LabelFrame(self.root, text="Binary Data", width=500, height=300, relief='groove', bd=2)
        self.details_frame = tk.LabelFrame(self.root, text="Packet Details", width=500, height=300, relief='groove', bd=2)

        self.packet_listbox = tk.Listbox(self.packet_list_frame, bd=1, relief="groove", selectborderwidth=2,
                                         width=650, height=800, listvariable=tk.StringVar(value=dictionary.header_info),
                                         activestyle="none", selectmode='single')
        self.binary_data_box = tk.Text(self.binary_frame, width=68, height=40, selectbackground="black")
        self.details_text = tk.Text(self.details_frame, width=68, height=40)

        self.packet_list_scrollbar = tk.Scrollbar(self.packet_list_frame, orient=tk.VERTICAL)
        self.binary_data_scrollbar = tk.Scrollbar(self.binary_frame, orient=tk.VERTICAL)
        self.details_scrollbar = tk.Scrollbar(self.details_frame, orient=tk.VERTICAL)

        self.packet_listbox.config(yscrollcommand=self.packet_list_scrollbar.set)
        self.packet_list_scrollbar.config(command=self.packet_listbox.yview)

        self.packet_list_frame.place(x=0, y=0)
        self.packet_list_frame.pack(side=tk.RIGHT, fill="y", expand=False)
        self.packet_list_frame.propagate(False)
        self.packet_listbox.pack(side=tk.LEFT)
        self.packet_list_scrollbar.pack(side=tk.RIGHT, fill="y")

        self.packet_listbox.bind('<Button-1>', self.on_packet_selected)

        self.binary_data_box.config(yscrollcommand=self.binary_data_scrollbar.set)
        self.binary_data_scrollbar.config(command=self.binary_data_box.yview)
        self.binary_data_box.pack(side=tk.LEFT, fill="both", expand=True)
        self.binary_frame.pack(fill="both", expand=True)
        self.binary_frame.propagate(False)

        self.binary_data_box.insert(tk.INSERT, dictionary.pack_con)
        self.details_text.insert(tk.INSERT, dictionary.analyse_info)

        self.details_scrollbar.pack(side=tk.RIGHT, fill="y")
        self.details_text.config(yscrollcommand=self.details_scrollbar.set)
        self.details_scrollbar.config(command=self.details_text.yview)
        
        self.details_text.pack()
        self.details_frame.pack(fill="both", expand=True)
        self.details_frame.propagate(False)

    def on_packet_selected(self, event):
        if self.packet_listbox.curselection():
            selected_packet = self.packet_listbox.get(self.packet_listbox.curselection())
            dictionary.which_pack_is_selected = selected_packet
            self.analyse_selected_packet()

    def periodic_refresh(self):
        while True:
            self.update_packet_list_display()
            time.sleep(1) #每一秒刷新一次数据包显示

    def update_packet_list_display(self):
        self.packet_listbox.delete(0, tk.END)
        dictionary.dict_keys = list(dictionary.dict.keys())
        for key in dictionary.dict_keys:
            self.packet_listbox.insert(tk.END, key)
        self.packet_listbox.update()

    def analyse_selected_packet(self):
        dictionary.pack_con = dictionary.dict.get(dictionary.which_pack_is_selected, "")
        self.binary_data_box.delete('1.0', tk.END)
        self.binary_data_box.insert(tk.END, dictionary.pack_con)
        self.binary_data_box.update()

        analyze.analyse()
        analyze.connect_info()

        self.details_text.delete('1.0', tk.END)
        self.details_text.insert(tk.INSERT, dictionary.analyse_info)
        self.details_text.update()

    def start(self):
        self.root.mainloop()

if __name__ == '__main__':
    app = NetworkSnifferGUI()
    app.start()