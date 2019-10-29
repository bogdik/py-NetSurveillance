#!/usr/bin/python
import socket,time,re,sys,getopt,json,binascii,struct

class ChinaCam():
 
    def __init__(self, ip,port,passwd):
        """Constructor"""
        self.ip = ip
        self.port = port
        self.passwd = passwd
	if not self.passwd:
		self.passwd='tlJwpbo6'
	self.command_codes = {
		"KeepAlive": 1006,
		"ConfigSet": 1040,
		"ConfigGet": 1042,
		"EncodeCapability": 1360,
		"SystemFunction": 1360

	}
        self.commands={
            'SystemFunction':{'strPrep':'00000002000000000050053a000000','length':5454},
            'SystemInfo': {'strPrep': '0000000d0000000000fc0336000000', 'length': 664},
            'General.General':{'strPrep':'00000010000000000012043b000000','length':322},
            'General.Location':{'strPrep':'00000011000000000012043c000000','length':481},
            'NetWork.NetCommon':{'strPrep':'00000013000000000012043d000000','length':431},
            'NetWork.NetDNS':{'strPrep':'00000015000000000012043a000000','length':172},
            'NetWork.IPAdaptive':{'strPrep':'00000016000000000012043e000000','length':172},
            'NetWork.NetDHCP':{'strPrep':'00000014000000000012043b000000','length':337},
            'NetWork.OnvifPwdCheckout':{'strPrep':'000000b20000000000100470000000','length':337},
            'OEMcfg.Correspondent':{'strPrep':'000000190000000000120440000000','length':507},
            'Camera': {'strPrep': '0000000f0000000000500532000000', 'length': 384},
            'SupportExtRecord': {'strPrep': '00000010000000000050053c000000', 'length': 149},
            'ChannelTitle': {'strPrep': '000000110000000000180438000000', 'length': 320},
            'OPTimeQuery': {'strPrep': '0000000d0000000000ac0537000000', 'length': 150},
            'MaxPreRecord': {'strPrep': '0000000e0000000000500538000000', 'length': 150},
            'Storage.StoragePosition': {'strPrep': '0000000f0000000000120443000000', 'length': 200},
            'Record.': {'strPrep': '000000100000000000120436000000', 'length': 2000},
            'OPMachine': {'strPrep': '0000000c0000000000aa0555000000', 'length': 300},
        }
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn.connect((ip, self.port))
        self.conn.send('')
        time.sleep(0.1)
        dataAuth='ff00000000000000000000000000e80364000000'+('{ "EncryptType" : "MD5", "LoginType" : "DVRIP-Web", "PassWord" : "'+self.passwd+'", "UserName" : "admin" }').encode('hex')+'0a'
        self.conn.send(dataAuth.decode('hex'))
        time.sleep(0.1)
        dataAuthRet = self.conn.recv(300)
	self.countPacketsSend=1
        sessid=repr(dataAuthRet)
        sessid=re.findall(r'"SessionID" : ".+"', sessid)[0]
        self.sessid=sessid.split(':')[1].replace(' "','').replace('"','')
        self.forpreset=self.sessid.split('x')[1]

    def build_packet(self, input_data, message_code, encoding="ascii"):
	data=input_data
	unknown_block_0 = b"\x00\x00\x00"
	sequence_number = chr(self.countPacketsSend)
	unknown_block_1 = b"\x00\x00\x00\x00\x00"
	message_byte = struct.pack('<H', message_code)
	data_len = struct.pack('<I', len(data) + 1)
	retdata=(unknown_block_0 + sequence_number + unknown_block_1 + message_byte + data_len).encode('hex')
	return retdata

    def getCommList(self):
        return self.commands.keys()

    def closeConnect(self):
        return self.sendCommand('',cusPrep='000000000000000000de052c000000')

    def sendCommand(self,command,shortSess=False,cusPrep=False,cusDopParam='',cusDopName='',noWait=False,message_code=1042,buildPacket=False):
        result=False
        if shortSess:
            sessid='0x'+self.forpreset.lstrip('0')
        else:
            sessid=self.sessid

        if command in self.commands.keys() and cusPrep==False:
            cmdSendPr=command
            if cusDopName:
                cmdSendPr=command+cusDopName
	    packetSend='ff'+self.forpreset+self.commands[command]['strPrep']+('{ "Name" : "'+cmdSendPr+'",'+cusDopParam+' "SessionID" : "'+sessid+'" }').encode('hex')+'0a'
        elif cusPrep:
	    cmdSend='{ "Name" : "'+command+'",'+cusDopParam+' "SessionID" : "'+sessid+'" }'
	    if message_code==1042:
		conf=self.command_codes['ConfigGet']
	    else:
		conf=self.command_codes['ConfigSet']
	    if buildPacket:
		cusPrep=self.build_packet(cmdSend,conf)		
            packetSend='ff'+self.forpreset+cusPrep+('{ "Name" : "'+command+'",'+cusDopParam+' "SessionID" : "'+sessid+'" }').encode('hex')+'0a'
	    #print(packetSend)
        elif not command in self.commands.keys() and cusPrep==False:
            cmdSendPr=command
            if cusDopName:
                cmdSendPr=command+cusDopName
	    cmdSend='{ "Name" : "'+cmdSendPr+'",'+cusDopParam+' "SessionID" : "'+sessid+'" }'
	    if message_code==1042:
		conf=self.command_codes['ConfigGet']
	    else:
		conf=self.command_codes['ConfigSet']
            packetSend='ff'+self.forpreset+self.build_packet(cmdSend,conf)+(cmdSend).encode('hex')+'0a'
	self.countPacketsSend += 1
        self.conn.send(packetSend.decode('hex'))
        time.sleep(0.1)
        if noWait:
            return True
        if command=='':
            data = self.conn.recv(300)
        else:
            data = self.conn.recv(self.commands[command]['length'])
        try:
            data='{'+repr(data).split("{", 1)[1].replace("}\\n\\x00'",'}').replace("\\n'",'').strip()
            result =json.loads(data)
        except:
            print(data)
        if result:
            return result
        return False

    def reboot(self):
        cusPrep='000000150000000000aa0555000000'
        print ("Reboot camera")
        self.sendCommand('General.General')
        time.sleep(0.5)
        self.sendCommand('General.Location')
        time.sleep(0.5)
        self.sendCommand('OPTimeQuery')
        print("Please wait 30 seconds")
        time.sleep(0.5)
        self.sendCommand('OPMachine',True,cusPrep,' "OPMachine" : { "Action" : "Reboot" },',noWait=True)
        self.closeConnect()


    def DHCP(self,interface='eth0',state=False):
        getDhcpState=self.sendCommand('NetWork.NetDHCP')
        changeState=False
        result=False
        for iface in getDhcpState['NetWork.NetDHCP']:
            if interface==iface['Interface'] and state!=iface['Enable']:
                iface['Enable']=state
                changeState=True
        del getDhcpState['Ret']
        del getDhcpState['Name']
        del getDhcpState['SessionID']
        if state:
            cusPrep='000000280000000000100428010000'
        else:
            cusPrep='0000001a0000000000100429010000'
        if changeState:
            print ("Change state DHCP")
            result=self.sendCommand('NetWork.NetDHCP',True,cusPrep,' '+json.dumps(getDhcpState,sort_keys=True)[1:-3].replace(': ',' : ').replace('" : [{','" : [ {' ).replace('}, {',' }, { ')+' } ],',buildPacket=True,message_code=1040)
        else:
            print ("No need change state DHCP")
            return True
        if result:
            if result['Ret']==100:
                return True
        else:
            if state:
                result=self.sendCommand('NetWork.IPAdaptive',True,'000000290000000000100467000000',' "NetWork.IPAdaptive": { "IPAdaptive": true },')
                if result:
                    if result['Ret']==100:
                        return True
        return False

    def RovertNet(self,val):
	return val[6]+val[7]+val[4]+val[5]+val[2]+val[3]+val[0]+val[1]

    def Network(self,ip=False,mask=False,gateway=False,httport=80):
        getNet=self.sendCommand('NetWork.NetCommon')
        changeState=False
        result=False
        if ip:
            ip='0x'+self.RovertNet(binascii.hexlify(socket.inet_aton(ip))).upper()
        if mask:
            mask='0x'+self.RovertNet(binascii.hexlify(socket.inet_aton(mask))).upper()
        if gateway:
            gateway='0x'+self.RovertNet(binascii.hexlify(socket.inet_aton(gateway))).upper()
        cusPrep = '000000470000000000100487010000'
        for cfg in getNet['NetWork.NetCommon']:
            if cfg=='HostIP' and getNet['NetWork.NetCommon'][cfg]!=ip and ip:
                getNet['NetWork.NetCommon'][cfg]=ip
                changeState=True
            if cfg=='Submask' and getNet['NetWork.NetCommon'][cfg]!=mask and mask:
		print("Change NETMASK")
                getNet['NetWork.NetCommon'][cfg]=mask
                changeState=True
            if cfg=='GateWay' and getNet['NetWork.NetCommon'][cfg]!=gateway and gateway:
		print("Change gateway")
                getNet['NetWork.NetCommon'][cfg]=gateway
                changeState=True
            if cfg=='HttpPort' and getNet['NetWork.NetCommon'][cfg]!=httport and httport:
		print("Change http port")
                getNet['NetWork.NetCommon'][cfg]=httport
                changeState=True
        del getNet['Ret']
        del getNet['Name']
        del getNet['SessionID']
        if changeState:
	    self.DHCP();
            self.sendCommand('NetWork.IPAdaptive', True, '000000290000000000100467000000',' "NetWork.IPAdaptive": { "IPAdaptive": false },',buildPacket=True)
            time.sleep(0.2)
            self.sendCommand('NetWork.OnvifPwdCheckout', True, '000000ea0000000000100470000000',' "NetWork.OnvifPwdCheckout": { "Enable" : false },',buildPacket=True)
            time.sleep(0.2)
            #print(' ' + json.dumps(getNet, sort_keys=True)[1:-3].replace(': ',' : ').replace( '" : [{', '" : [ {').replace('}, {', ' }, { ') + ' } ],')
            print ("Change network settings")
	    time.sleep(0.2)
            result = self.sendCommand('NetWork.NetCommon', True, cusPrep,' ' + json.dumps(getNet, sort_keys=True)[1:-2].replace(': ',' : ').replace(' {"G', ' { "G').replace( '" : [{', '" : [ {').replace('}, {', ' }, { ') + ' },',buildPacket=True,noWait=True,message_code=1040)
            print(result)
        else:
            print ("No need change network settings")
            return True
        return False

if __name__ == "__main__":
    ip='192.168.1.10'
    port = 34567
    passwd=''
    command=''
    options=''
    res=''
    listSh=False
    try:
        opts, args =getopt.getopt(sys.argv[1:], 'i:p:pt:c:o:l:', ['i=', 'pt=','p=', 'c=', 'l='])
    except getopt.GetoptError:
        print('cam.py -i <ipaddress> (default 192.16.1.10) -pt <port> (default 34567) -p <password> -c <Command> -o <Options> -l <Boolean> (show list commands)')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('cam.py -i <ipaddress> (default 192.16.1.10) -pt <port> (default 34567) -p <password> -c <Command> -o <Options> -l <Boolean> (show list commands)')
            sys.exit()
        elif opt in ("-i", "--ip"):
            ip = arg
        elif opt in ("-pt", "--port"):
            port = int(arg)
        elif opt in ("-p", "--pass"):
            passwd = arg
        elif opt in ("-c", "--command"):
            command = arg
        elif opt in ("-o", "--options"):
            options = arg
        elif opt in ("-l", "--list"):
            listSh=True
    if command=='' and not listSh:
        print('You need inpute command for help use -h')
        sys.exit(2)
    cam = ChinaCam(ip,port,passwd)
    if listSh:
        comms=cam.getCommList()
        comms={'Information':comms,'Configurations':['dhcp','network','reboot']}
        print(comms)
        cam.closeConnect()
        sys.exit(2)
    if command=='dhcp':
        options=options.split(',')
        if len(options)==2:
            if not 'eth' in options[0]:
                print('Unknown interface example:`-c dhcp -o eth0,false` for get info use `-c NetWork.NetDHCP`')
                cam.closeConnect()
                sys.exit(2)
            elif options[1]!='false' and options[1]!='true':
                print('Unknown param (true or false) example:`-c dhcp -o eth0,false`')
                cam.closeConnect()
                sys.exit(2)
            else:
                if options[1]=='true':
                    options[1]=True
                else:
                    options[1]=False
                res=cam.DHCP(options[0],options[1])
        else:
            print('No needed options for DHCP example:`-c dhcp -o eth0,false`')
            cam.closeConnect()
            sys.exit(2)
    elif command=='network':
	if not options:
	    print('No needed options for Network example:`-c network -o 192.168.1.10,255.255.255.0,192.168.1.1`')
            cam.closeConnect()
            sys.exit(2)
	options=options.split(',')
	ip=False
	mask=False
	gateway=False
	httport=False
        if len(options)==4:
		ip=options[0]
		mask=options[1]
		gateway=options[2]
		httport=options[3]
        elif len(options)==3:
		ip=options[0]
		mask=options[1]
		gateway=options[2]
        elif len(options)==2:
		ip=options[0]
		mask=options[1]
        else:
		ip=options
	cam.Network(ip,mask,gateway,httport)

    elif command=='Record':
        options = options.split(',')
        if len(options) == 2:
            if not options[1] or not type(int(options[1])) is int:
                print("In options input id record  example:`-c Record -o get,0`")
                cam.closeConnect()
                sys.exit(2)
            elif options[0]!='get' and options[0]!='set':
                print("No action option  example:`-c Record -o get,0`")
                cam.closeConnect()
                sys.exit(2)
            else:
                if options[0]=='get':
                    res = cam.sendCommand(command+'.',cusDopName='['+options[1]+']')
                    if not command+'.['+options[1]+']' in res.keys():
                        print("Not found")
                    else:
                        print(res[command+'.['+options[1]+']'])
                else:
                    print("No realise functional")
        else:
            print('No needed options for Record example:`-c Record -o get,0`')
            cam.closeConnect()
            sys.exit(2)
    elif command=='reboot':
            lastID=cam.sessid
            cam.reboot()
            time.sleep(30)
            try:
                cam = ChinaCam(ip, port, passwd)
                if lastID!=cam.sessid:
                    print("Camera rebootes success")
                cam.closeConnect()
            except:
                print("Camera reboot bad")

    else:
        res=cam.sendCommand(command)
        if not res:
            print("Error on camera command complite")
        elif res['Ret']!=100:
            print("Camera not supported this command")
        else:
            print(res[command])
    #print ('end')
    cam.closeConnect()
