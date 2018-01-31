import nmap
nm = nmap.PortScanner()


with open("IP_address_bridges.txt") as f:
	for IP_address in f: 
		IP_address = IP_address.rstrip()
		print "IP address " + IP_address
		nm.scan(IP_address, arguments="-O -sS -v -sV")
		if 'osmatch' in nm[IP_address]:
			if len(nm[IP_address]['osmatch']) == 0:
				print "no OS data?"
				#print nm[IP_address]
			else:
				for osclass in nm[IP_address]['osmatch'][0]['osclass']:
#					print('OsClass.vendor : {0}'.format(osclass['vendor']))
#					print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
#					print('OsClass.type : {0}'.format(osclass['type']))
#					print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
#					print('')

					with open("os_data_bridges.json", "a") as myfile:
						myfile.write('{"IP_address": "' + IP_address + '", "vendor": "' + osclass['vendor'] + '", "osfamily": "' + osclass['osfamily']+'", "type": "' +osclass['type'] +'", "accuracy": "' +osclass['accuracy']+'"}\n')
