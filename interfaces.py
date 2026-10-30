from scapy.all import conf, get_if_list

print("All interfaces:", get_if_list())
print("Default interface:", conf.iface)