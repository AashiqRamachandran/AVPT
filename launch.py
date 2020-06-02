import pyshark
import csv
import nmap

nmap_scanner=nmap.PortScanner()
writer_file=open("IP.csv","a")
log=csv.writer(writer_file)

cap=pyshark.LiveCapture(interface="eth0")
cap.sniff(timeout=1)
for packet in cap.sniff_continuously():
    if packet.src.ip in log:
        continue
    else:
        open_ports= nmap_scanner(packet.src.ip)
        #usually over here we are going to have to add many many more VAPT tools
        #also have to write those objects to our csv file
        #oh and dont forget to import them and add them to the requirements file
        log.writerow([packet.src.ip, open_ports])
     
