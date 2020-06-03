import pyshark
import csv
import nmap3

def check(ip):
    with open("IP.csv", 'rt') as f:
    	reader = csv.reader(f, delimiter=',')         
    	if ip in reader:
    	    return 1
    	else:
    	    return 0
        
nm=nmap3.Nmap()
writer_file=open("IP.csv","a")
log=csv.writer(writer_file)

cap=pyshark.LiveCapture(interface="eth0")
cap.sniff(timeout=1)
for packet in cap.sniff_continuously():
    if 'IP' in packet:
	    src=packet.ip.src
	    option=check(src)
	    if option==1:
	        continue
	    else:
	        print("New IP address ["+packet.ip.src+"] has just arrived.")
	        data_from_nmap= nm.scan_top_ports(packet.ip.src)
		os_results = nm.nmap_os_detection(packet.ip.src)
	        print(data_from_nmap)
		print(os_results)
	        #usually over here we are going to have to add many many more VAPT tools
	        #also have to write those objects to our csv file
	        #oh and dont forget to import them and add them to the requirements file
	        log.writerow([packet.ip.src, data_from_nmap, os_results])
