import nmap
nm = nmap.PortScanner()
IP_address = "127.0.0.1"
nm.scan(IP_address, arguments="-O")
if 'osclass' in nm[IP_address]:
    for osclass in nm[IP_address]['osclass']:
        print('OsClass.type : {0}'.format(osclass['type']))
        print('OsClass.vendor : {0}'.format(osclass['vendor']))
        print('OsClass.osfamily : {0}'.format(osclass['osfamily']))
        print('OsClass.osgen : {0}'.format(osclass['osgen']))
        print('OsClass.accuracy : {0}'.format(osclass['accuracy']))
        print('')
