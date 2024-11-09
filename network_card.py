import tkinter
import dictionary
from winpcapy import WinPcapDevices


with WinPcapDevices() as devices:
    for device in devices:
        str_network_card = str(device.description)
        dictionary.network_card_info_list.append(str(str_network_card[2:len(str_network_card) - 1]))


def get_network_card_info():
    network_info = tkinter.Tk()
    network_info.title("网卡：")
    network_info.geometry("400x350+550+200")
    lf = tkinter.LabelFrame(network_info, text="请选择要抓包的网卡:", width=420, height=350, relief='groove', bd=2)
    lf.pack()

    network_info.propagate(False)

    net_info_box = tkinter.Listbox(lf, width=50, height=15, selectmode='singe', activestyle='none')
    for item in dictionary.network_card_info_list:
        net_info_box.insert(tkinter.END, item)
    net_info_box.propagate(False)
    net_info_box.pack()


    def selected_item(event):
        if len(net_info_box.curselection()) != 0:
            dictionary.checked_packet = net_info_box.get(net_info_box.curselection())

    net_info_box.bind('<ButtonRelease-1>', selected_item)

    def clo_win():
        network_info.destroy()

    tkinter.Button(lf, text="确定", command=clo_win).pack()

    network_info.mainloop()


def close_widow(root):
    root.protocol('WM_DELETE_WINDOW', root.destroy)


def set_value(num):
    dictionary.checked_packet = num
