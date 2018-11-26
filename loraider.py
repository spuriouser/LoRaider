#!/usr/bin/python

import csv
import json
import math
from os import listdir
from os.path import isfile, join
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from operator import itemgetter
import curses
import curses.textpad
import locale

locale.setlocale(locale.LC_ALL, '')
directory="./"

#LoRaWAN message types
JOIN="0"
JOIN_ACCEPT="1"
UUPLINK="2"
UDOWNLINK="3"
UPLINK="4"
DOWNLINK="5"
RWJOIN="6"
PROPRIETARY="7"

#selected menu options
MAIN=0
SORT=1
PACKETS=2
KEYS=3

sortWindow=0
wnodeWindow=0
packetWindow=0
keysWindow=0
alertWindow=0

currentSorted=0
oldSorted=8

nodes={}
keys=[] # load and save keys to file
selectedLine=0
selectedPacket=0
scrollOffset=0
packetOffset=0
selectedSort=10
selectedKeysItem=0 #0=appskey, 1=nwkskey, 2=ok.
sortDirection=True
currentWindow=MAIN
title="LoRaider v0.1"

DEFAULT=1
SELECTED=2
HEADER=3
MENU=4
PACKETMENU=5
ALERT=6

#structure: Column name, minimum column spaces, node dictionary reference, enabled by default.
headers=[("Node ID",9, "DevAddr", True),
	 ("Packets",10, "numPackets", True),
	 ("Lengths",8, "lengths",True),
	 ("Types", 7, "types", True),
	 ("Channels",10,"channels", True),
	 ("Ports",6,"ports", True),
	 ("SFs",7,"sfs", True),
	 ("<"+u'\u0394'.encode('utf-8')+"t>",12,"deltaT",False),
	 ('var('+u"\u0394".encode('utf-8')+'t)',12,"varDeltaT",False),
	 ("D",2,"IsDecrypted",True),
	 ("First Seen",22,"FirstTime",True),
	 ("Last Seen",22,"LastTime",True),
	 ("<RSSI>",8,"avRSSI", True),("<SNR>",7,"avSNR", True),
	 ("Comment",20,"comment",False)]

packetHeaders= [("  #",4,"Number"),
		("FCnt",6,"FCnt"),
		("Date     Time",22,"Timestamp"),
		("Type", 10, "Type"),
		("Ch",3,"Channel"),
		("Port",5,"FPort"),
		("SF",3,"SF"),
		("FCtrl",6,"FCtrl"),
		("RSSI",6,"RSSI"),
		("SNR",6,"SNR"),
		("Length", 8, "Length"),
		("Payload", 30,"Payload")]

def alert(title, content):
	curses.curs_set(0) # in case this is still on from the keys window
	content=content.split("\n")
	height=len(content)
	width=len(title)
	for i in range(0,height):
		l=len(content[i])
		if l>width:
			width=l
	alertWindow=curses.newwin(height+4,width+4,int(bounds[0]/2-height/2-2),int(bounds[1]/2-width/2-2))
	for i in range(0,height):
		alertWindow.addstr(i+2,2,content[i])
	alertWindow.bkgd(curses.color_pair(ALERT))
	alertWindow.box()
	alertWindow.addstr(0,1,title)
	alertWindow.refresh()
	stdscr.getch() #block
	populateTableData(scrollOffset)

def truncateColumn(data, length):

	if type(data)==list: #if it's a list sort it and remove listy characters
		data=str(sorted(data)).translate(None, '\'[] ')
	if type(data)==bool:
		if data:
			data=u'\u2714'.encode('utf-8') #tick
		else:
			data=u'\u2718'.encode('utf-8') #cross
		return data
	data=str(data)
	l=len(data)
	if l>length:
		data=data[0:length]
		i=data.rfind(',') #remove the last comma and anything after it.
		if i==-1:
			i=length
		data=data[0:i-2]+u'\u2026'.encode('utf-8')
#		data=data[len(data)-2]
	return data

def getChannel(frequency):
	if  "8681" in frequency:
		return 1
	if "8683" in frequency:
		return 2
	if "8685" in frequency:
		return 3
	if "8671" in frequency:
		return 4
	if "8673" in frequency:
		return 5
	if "8675" in frequency:
		return 6
	if "8677" in frequency:
		return 7
	if "8670" in frequency:
		return 8
	return '?' #add more detail for unknown frequencies in packet detail pane

def  doSecurityChecks():
	duplicateCounters=""
	variablePayloads=""
	for n in nodes:
#check for duplicate counters in one node
		l=[]
		for p in nodes[n]["trace"]:
			if "FCnt" in p:
				l.append(p["FCnt"])
		if len(l)!=len(set(l)):
			for k in set(l):
				l.remove(k)
			duplicateCounters+=n+": "+str(sorted(list(set(l))))+"\n"
#			alert("Duplicate counters!","Node="+n+"\n"+str(list(set(l))))
			nodes[n]["Issues"]=nodes[n]["Issues"]+"\nDuplicate Counters: "+str(sorted(list(set(l))))+"\n" #converting to and from a set to unique the values

#check for varying payload lengths
		if "pLengths" in nodes[n] and len(nodes[n]["pLengths"])>1:
			#print n+"="+str(nodes[n]["lengths"])
			nodes[n]["Issues"]=nodes[n]["Issues"]+"\nVarying payload lengths"
#			alert("Varying payload",n+"="+str(nodes[n]['lengths']))
			variablePayloads+=n+": "+str(nodes[n]["lengths"])+"\n"
	alert("Security Summary", "Duplicate Counters:\n\n"+duplicateCounters+"\n\nVariable Payload Lengths:\n\n"+variablePayloads) #far too many variable length payloads to fit in the box

#look for
# duplicate counters within a node (use set to check for uniqueness)
# counters arriving out of sequence (sort by time, sort by counter, compare)
# varying payload lengths within a node
# orphaned node - unresponded JOIN requests
# maybe other network classes? or just list this separately.
#
#

#should probably put this and other methods into a helper module and base closely of the node.js package
def checkMIC(NwSKey, devAddr, packet):
	if packet["Type"]!="Uplink": #only deal with uplinks for now
		return False
	#calculate the MIC and compare to the payload of the packet
# Msg = MHDR | FHDR | FPort | FRMPayload
#B0 = (0x49 | 4*0x00 | Dir | DevAddr | FCntUp or FCntDown | 0x00 | len(msg) )
#mac = aes128_cmac(NwkSKey, B0 | msg)
#MIC = mac[0..3]
#Dir=0 for uplink, 1 for downlink
#assuming uplink packets only for now.
#devAddr needs to be little-endian
#FCNT needs to be 4 bytes - add 2 bytes of 00s to assume 32 bits. May also need to be Little Endian? need to insert fcnt manually again
#	print packet["FullPayload"]
#	print packet["FullPayload"][:-8]
	msg=packet["FullPayload"][:-8].decode("hex") #changed to -9 as was giving an error, though - worked before... some sort of off by one only triggered when fcnt!=0?
#	print "FCnt="+packet["FCnt"] #fcnt needs to be little-endian - and possibly guess MSBs! take off two of those following \x00s and update the decryption method too!
	B='\x49\x00\x00\x00\x00\x00'+devAddr.decode("hex")+packet["FCnt"][2:4].decode("hex")+packet["FCnt"][0:2].decode("hex")+"\x00\x00\x00"+chr(len(msg))
	msg=B+msg
#	print msg.encode("hex")
	cobj=CMAC.new(NwSKey.decode("hex"), ciphermod=AES)
	cobj.update(msg)
	MICcalc=cobj.hexdigest()
#	print MICcalc[0:8]
#	print packet["MIC"]
	if MICcalc[0:8].lower()==packet["MIC"].lower():
		return True
#	print MICcalc[0:8].lower() +"!="+ packet["MIC"].lower()
	return False

def decryptPayload(AppSKey, devAddr, packet):
	payload=packet["Payload"].decode('hex')
	k=int(math.ceil(float(len(payload))/16)) #assuming upload message for now
#	print payload+" len="+str(len(payload))
	S=""
	for i in range(1,k+1):
		A="\x01\x00\x00\x00\x00\x00"+devAddr.decode("hex")+packet["FCnt"][2:4].decode("hex")+packet["FCnt"][0:2].decode("hex")+"\x00\x00\x00"+chr(i)
#		print "key="+A.encode("hex")
		S=S+A
#	print "A="+S.encode("hex")+" length="+str(len(A))
	cobj=AES.new(AppSKey.decode("hex"), AES.MODE_ECB)
	cipherStream=cobj.encrypt(S)
#	print "Cipherstream="+cipherStream.encode("hex")
#xor the keystream and payload
	decrypted=''.join(chr(ord(a) ^ ord(b)) for a,b in zip(cipherStream,payload))
#	print "decrypted="+decrypted
	return decrypted

def addPacket(payload, timestamp, SF, frequency, RFChain, RXChain, codeRate, RSSI, SNR):
	channel=getChannel(frequency)
	node={}
	MHDR=payload[0:3] #not technically correct
	length=len(payload)
	MIC=payload[length-8:length]
	packet={}
	devAddr="UNDEFINED"
	packet['FullPayload']=payload
	packet['Number']=0 #fill this in later after sort
	packet['Length']=length
	packet['MIC']=MIC
	packet['SF']=int(SF[2:]) #cut off the leading "SF"
	packet['Timestamp']=timestamp[0:timestamp.rfind(".")]
	packet['Channel']=channel
	packet['RF']=RFChain
	packet['RX']=RXChain
	packet['CodeRate']=codeRate
	packet['RSSI']=RSSI
	packet['SNR']=SNR
#	print MHDR

	if MHDR[0]==UPLINK:
		packet['Type']="Uplink"
# DevAddr is listed little-endian
#Note that although the data is in hex, it's displayed as a string, so the byte lengths of everything are multiplied by 2!
		devAddr=payload[2:10]#payload[8:10]+payload[6:8]+payload[4:6]+payload[2:4]
		packet['FCtrl']=payload[10:12] #later we will break this out and have to take into account that the options length might be non-zero. THIS ACTUALLY EXPLAINS SOME OF THE LONGER PACKETS!
		packet['FOpts']={}
		packet['FOptsLen']=int(packet['FCtrl'],16) & 7
		packet['Payload']=payload[18+packet['FOptsLen']*2:len(payload)-8] # multiply foptslen x2 as each character is represented as a hex string
		packet['PayloadLength']=len(packet['Payload'])
		packet['FCnt']=payload[14:16]+payload[12:14] #later add support for LoRaWAN 1.1 NFCntDown213
		packet['FPort']=payload[16:18]
		packet['PLength']=len(packet['Payload']) # want to see if this changes for the node - regular length may just be some FOpts
#		checkMIC("99D58493D1205B43EFF938F0F66C339E", devAddr,packet)
#		checkMIC("A7CCDD6BA69FCCAEC0C3ABCACD98D68C", devAddr,packet)
#		decryptPayload("02618854EF073E9B028D7D254237A8A5", devAddr,packet)
#other boolean values to be added:
#ADR
#ACK
#FPending
#ClassB
#
	elif MHDR[0]==JOIN:
		packet['Type']="Join"

	else:
		packet['Type']="???"
	if devAddr in nodes:
		nodes[devAddr]['trace'].append(packet)
	else:
		nodes[devAddr]={"trace":[packet]}
		nodes[devAddr]['DevAddr']=devAddr

def calculateNodeStats():
#	print nodes
	for n in nodes:
		node=nodes[n]
		totalSNR=0.0
		totalRSSI=0
		numPackets=0
		vT=0
		numPackets=len(node["trace"])
		types=[]
		channels=[]
		lengths=[]
		pLengths=[]
		sfs=[]
		ports=[]
		#packets must be sorted in order of arrival time
#		print node["trace"]
		node["trace"]=sorted(node["trace"], key=itemgetter("Timestamp"))
		i=1
		for p in node["trace"]:
			p["Number"]=i
			i=i+1
		for p in node["trace"]:
			totalSNR=totalSNR+float(p['SNR'])
			totalRSSI=totalRSSI+int(p['RSSI'])
			l=p['Length']
			if not l in lengths:
 				lengths.append(l)
			if "PLength" in p:
				pl=p['PLength']
				if not pl in pLengths:
					pLengths.append(pl)
			t=p['Type'][0]
			if not t in types:
				types.append(t)
			c=p['Channel']
			if not c in channels:
				channels.append(c)
			if not p['SF'] in sfs:
				sfs.append(p['SF'])
			if 'FPort' in p and not  int(p['FPort']) in ports:
				ports.append(int(p['FPort']))
		node['numPackets']=numPackets
		node["avSNR"]=round(totalSNR/numPackets,1) #1d.p.
		node["avRSSI"]=int(totalRSSI/numPackets)
#update this so dictionaries print properly - maybe in that parsing routine for the ellipses instead. then we can keep the full dictionary here and we can sort the full list on it.
		node["lengths"]=sorted(lengths)
		node["pLengths"]=sorted(pLengths)
		node["types"]=sorted(types)
		node["channels"]=sorted(channels)
		node["sfs"]=sorted(sfs)
		node["ports"]=sorted(ports)
		firstTime=node["trace"][0]['Timestamp']
		lastTime=node["trace"][numPackets-1]['Timestamp']
		node["FirstTime"]=firstTime
		node["LastTime"]=lastTime
#		for p in node["trace"]:
#			vL=vL+(p['Length']-averageLength)**2 #calculate the variance of the length
#			vL=round(float(vL/numPackets),3)
		node["IsDecrypted"]=False
		node["AppKey"]="UNKNOWN"
		node["NwkSKey"]="UNKNOWN"
		node["AppSKey"]="UNKNOWN"
		node["Issues"]="" # store results of security checks, also used to highlight columns with issues
		for i in keys:
			if checkMIC(i[1],nodes[n]["DevAddr"],nodes[n]["trace"][0]):
				nodes[n]["IsDecrypted"]=True
				nodes[n]["NwkSKey"]=i[1]
				nodes[n]["AppSKey"]=i[2]
				for p in nodes[n]["trace"]:
					p["DecryptedPayload"]=decryptPayload(i[2],nodes[n]["DevAddr"], p)
		node["comment"]="test"

def printDebug():
	for n in nodes:
		print n
		print "\n"
		for o in nodes[n]:
			print o
		print "\n"

def processMainWindow(ch):
	global scrollOffset, selectedLine, sortWindow

#	print(str(ch))
	if ch==27 or ch==113 or ch==121: #Esc or q or Q
		curses.nocbreak
		stdscr.keypad(0)
		curses.echo()
		curses.endwin()
		exit()

	if ch==115 or ch==123: #s or S
		global currentWindow
		currentWindow=SORT
		sortWindow.redrawwin()
		updateSortWindow()
		return
	if ch==75 or ch==107: #k or K
		currentWindow=KEYS
		updateKeysWindow()
		keysWindow.redrawwin()
		return

	if ch==10 or ch==32: #Enter or Space
		global nodeWindow, selectedPacket, packetOffset
#reset the table counters
		selectedPacket=0
		packetOffset=0
		currentWindow=PACKETS
		nodeWindow.redrawwin()
		updateNodeWindow(0)
		return

	if nodes[currentSorted[scrollOffset+selectedLine]]["Issues"]!="":
		tableWindows[selectedLine].bkgd(curses.color_pair(ALERT))
	else:
		tableWindows[selectedLine].bkgd(curses.color_pair(DEFAULT))
	tableWindows[selectedLine].refresh()

	scrollChange=False
	if ch==curses.KEY_UP:
		if selectedLine>0:
			selectedLine=selectedLine-1
		else:
#update the scroll in the table
			if scrollOffset>0:
				scrollOffset=scrollOffset-1
				scrollChange=True;
	elif ch==curses.KEY_DOWN:
		if bounds[0]-4-selectedLine>0 and selectedLine<(len(nodes)-1):
			selectedLine=selectedLine+1
		else:
#update the scroll in the table
			if scrollOffset<len(nodes)-len(tableWindows):
				scrollOffset=scrollOffset+1
				scrollChange=True
	elif ch==curses.KEY_PPAGE:
		scrollOffset=(scrollOffset-int(len(tableWindows)/2))
		if scrollOffset<0:
			scrollOffset=0
		scrollChange=True
		selectedLine=0

	elif ch==curses.KEY_NPAGE:
		scrollOffset=((scrollOffset+int(len(tableWindows)/2)))
		if scrollOffset>(len(nodes)-len(tableWindows)):
			scrollOffset=len(nodes)-len(tableWindows)
		scrollChange=True
		selectedLine=len(tableWindows)-1
	if scrollChange:
		populateTableData(scrollOffset)

	tableWindows[selectedLine].bkgd(curses.color_pair(SELECTED))
	tableWindows[selectedLine].refresh()

def processSortWindow(ch):
	global scrollOffset, currentWindow, selectedSort, currentSorted, oldSorted, sortDirection
        if ch==27 or ch==113 or ch==121 or ch==10 or ch==32: #ESc or q or Q or Enter or Space
		if ch==10 or ch==32: #Enter or Space
#set the sorted list of node names based on the selected header. Field 2 is the dictionary reference for that header.
			if (selectedSort!=oldSorted):
				sortDirection=False
			else:
				sortDirection= not sortDirection #if we sort by the same column twice sort in the reverse order
			currentSorted=sorted(nodes, key=lambda x: nodes[x][headers[selectedSort][2]],reverse=sortDirection)
			oldSorted=selectedSort
		else:
			selectedSort=oldSorted
		populateTableData(scrollOffset)
		currentWindow=MAIN

		return
	half=int(len(headers)/2)
	if ch==curses.KEY_DOWN and selectedSort!=(len(headers)-1):
		selectedSort=selectedSort+1
	elif ch==curses.KEY_UP and selectedSort!=0:
		selectedSort=selectedSort-1
	elif ch==curses.KEY_RIGHT and (int(selectedSort/half))==0:
		selectedSort=selectedSort+int(len(headers)/2)
	elif ch==curses.KEY_LEFT and (int(selectedSort/half))==1:
		selectedSort=selectedSort-int(len(headers)/2)
	updateSortWindow()
def validateTextBoxInput(ch):
	global selectedKeysItem
#add something to check these are all hex values
	if ch==10 or ch==curses.KEY_DOWN:
		selectedKeysItem=selectedKeysItem+1
		return 7 #terminate editing
	if ch==curses.KEY_UP:
		selectedKeysItem=selectedKeysItem-1
		return 7
	if chr(ch) in "0123456789abcdefABCDEF":
		return (""+chr(ch)).upper()
	else:
		return None

def processKeysWindow(ch):
	global selectedKeysItem, currentWindow, scrollOffset
	if ch==27 or ch==113 or ch==121: #Esc or q or Q
		populateTableData(scrollOffset)
		currentWindow=MAIN
		return
	if ch==10:  #enter
		if selectedKeysItem==2:
			validKeys=False
			for n in nodes:
				nwkSKey=nwkSKeyBox.gather().strip()
				if checkMIC(nwkSKey,nodes[n]["DevAddr"],nodes[n]["trace"][0]):
					validKeys=True
					appSKey=appSKeyBox.gather().strip()
					nodes[n]["IsDecrypted"]=True
					nodes[n]["NwkSKey"]=nwkSKey
					nodes[n]["AppSKey"]=appSKey
					for p in nodes[n]["trace"]:
						p["DecryptedPayload"]=decryptPayload(appSKey,nodes[n]["DevAddr"], p) #decrypt all those payloads!
					alertString="The following keys decrypted traffic for node "+n+":\n\n\tNwkSKey:\t"+nwkSKey+"\n\tAppSKey:\t"+appSKey+"\n\nPayloads:\n"
					for i in range(0,3):
						alertString=alertString+"\n"+nodes[n]["trace"][i]["DecryptedPayload"]
					l=len(nodes[n]["trace"])
					if l>3:
						alertString=alertString+"\n\n+"+str(l-3)+" more."
					alert("Decrypted payload(s)", alertString);
					f=open('./keys.lst','a')
					f.write(n+","+nwkSKey+","+appSKey+"\n")
					f.close()
			if not validKeys:
				alert("Bad keys", "The NwkSKey "+nwkSKey+"\ndid not validate against any tested MIC.")
		elif selectedKeysItem==3:
			a=1; #we've cancelled
		populateTableData(scrollOffset)
		currentWindow=MAIN

	elif ch==curses.KEY_DOWN and selectedKeysItem < 12: # add a check that we're under the max value once we know what this is.
		selectedKeysItem=selectedKeysItem+1
		updateKeysWindow()

	elif ch==curses.KEY_UP and selectedKeysItem>0:
		selectedKeysItem=selectedKeysItem-1
		updateKeysWindow()

def processNodeWindow(ch):
        global currentWindow, selectedPacket, packetOffset, packetBounds
	if ch==27 or ch==113 or ch==121: #Esc or q or Q
                populateTableData(scrollOffset)
                currentWindow=MAIN
		return

	if ch==10 or ch==32: #Enter or Space
		a=1 #pull up more detail on the packet

	nodeWindows[selectedPacket].bkgd(curses.color_pair(PACKETMENU))
	nodeWindows[selectedPacket].refresh()

	scrollChange=False
	t=nodes[currentSorted[scrollOffset+selectedLine]]["trace"] #current selected packet trace
	if ch==curses.KEY_UP:
		if selectedPacket>0:
			selectedPacket=selectedPacket-1
		else:
			if packetOffset>0:
				packetOffset=packetOffset-1
				scrollChange=True
	elif ch==curses.KEY_DOWN:
		if ((packetBounds[0]-4-selectedPacket)>0) and selectedPacket<(len(t)-1):
			selectedPacket=selectedPacket+1
		else:
			if packetOffset<len(t)-len(nodeWindows):
				packetOffset=packetOffset+1
				scrollChange=True
	elif ch==curses.KEY_PPAGE:
		packetOffset=(packetOffset-int(len(nodeWindows)/2))
		if packetOffset<0:
			packetOffset=0
		scrollChange=True
		selectedPacket=0

	elif ch==curses.KEY_NPAGE:
		packetOffset=(packetOffset+int(len(nodeWindows)/2))
		if packetOffset>(len(t)-len(nodeWindows)):
			packetOffset=len(t)-len(nodeWindows)
		scrollChange=True
		selectedPacket=len(nodeWindows)-1

	if scrollChange:
		updateNodeWindow(packetOffset)
	nodeWindows[selectedPacket].bkgd(curses.color_pair(SELECTED))
	nodeWindows[selectedPacket].refresh()

	indexString=str(str(packetOffset+selectedPacket+1)+"/"+str(len(t)))
	nodeWindow.move(packetBounds[0]-1, packetBounds[1]-len(indexString)-1)
	nodeWindow.addstr(indexString)
	nodeWindow.hline(packetBounds[0]-1, packetBounds[1]-10, curses.ACS_HLINE, 9-len(indexString))
	nodeWindow.refresh()

def updateNodeWindow(index):
	global nodeWindow, nodeWindows, scrollOffset, selectedLine, packetBounds
	nodeWindow.addstr(0,1,"Node:"+currentSorted[scrollOffset+selectedLine])
	packets=nodes[currentSorted[scrollOffset+selectedLine]]["trace"]
	i=0
	l=0
	nodeWindow.refresh()
        for h in packetHeaders:
		if h[0]=="Payload":
			packetHeaderWindow.addstr(0,l+2,h[0])
		else:
			packetHeaderWindow.addstr(0,l+h[1]-len(h[0]),h[0]) #right align
        	        l=l+h[1]
	packetHeaderWindow.refresh()
	packetHeaderWindow.redrawwin() #maybe all this header stuff sholdn't be called every time
#let the payload take the rest of the screen as it needs
	lastIndex=len(packetHeaders)-1 #find the payload tuple
	packetHeaders[lastIndex]=("Payload", packetBounds[1]-l-4,"Payload")
	while i<packetBounds[0]-3 and i<len(packets):
		nodeWindows[i].erase()
		l=0
		if i==selectedPacket:
			nodeWindows[i].bkgd(curses.color_pair(SELECTED)) #PACKETSELECTION))
		else:
			nodeWindows[i].bkgd(curses.color_pair(PACKETMENU))
		for h in packetHeaders:
			data=str(packets[packetOffset+i][h[2]])
			if h[2]=="Payload": #left align and increase length
#use the decrypted version if we have it!
				if "DecryptedPayload" in packets[packetOffset+i].keys():
					data=packets[packetOffset+i]["DecryptedPayload"]
				data=truncateColumn(data,(packetBounds[1]-l-4))
				nodeWindows[i].addstr(0,l+2,data)
			else:
				nodeWindows[i].addstr(0,l+h[1]-len(data),data)
				l=l+h[1]
		nodeWindows[i].refresh()
		i=i+1
	indexString=str(str(packetOffset+selectedPacket+1)+"/"+str(len(packets)))
	nodeWindow.move(packetBounds[0]-1, packetBounds[1]-len(indexString)-1)
	nodeWindow.addstr(indexString)
	nodeWindow.hline(packetBounds[0]-1, packetBounds[1]-10, curses.ACS_HLINE, 9-len(indexString))
	nodeWindow.refresh()

def updateKeysWindow():
	global keysWindow,appSKeyBox, nwkSKeyBox, selectedKeysItem
	curses.curs_set(1)
	keysWindow.addstr(1, 2, "Enter key data:")
	keysWindow.addstr(4,6,"AppSKey:")
	keysWindow.addstr(3,6,"NwkSKey:")
	keysWindow.addstr(8,2, "Enter JOIN data (blank values to crack):")
	keysWindow.addstr(10,7,"AppKey: ")
	keysWindow.addstr(11,5, "DevNonce: ")
	keysWindow.addstr(12,5, "AppNonce: ")
	keysWindow.addstr(11,21, "NetID: ")
	keysWindow.addstr(12,21, "DevID: ")
	keyBounds=keysWindow.getmaxyx()
	keysWindow.hline(7, 1, curses.ACS_HLINE, keyBounds[1]-2)
	keysWindow.refresh()
	simpleOK=keysWindow.derwin(1,8,6,int(keyBounds[1]/2)-9)
	if selectedKeysItem==2:
		simpleOK.attron(curses.A_REVERSE)
	else:
		simpleOK.attroff(curses.A_REVERSE)
	simpleOK.addstr(0,4,"OK")
	simpleOK.refresh()
	simpleCancel=keysWindow.derwin(1,8,6,int(keyBounds[1]/2)+1)
	if selectedKeysItem==3:
		simpleCancel.attron(curses.A_REVERSE)
	else:
		simpleCancel.attroff(curses.A_REVERSE)
	simpleCancel.addstr(0,1,"Cancel")
	simpleCancel.refresh()

	if selectedKeysItem==9:
		a=1
	else:
		a=1

	if selectedKeysItem==10:
		a=1
	else:
		a=1

	keysWindow.refresh()

	while selectedKeysItem<2 or selectedKeysItem>3:
		if selectedKeysItem==0:
			nwkSKeyBox.edit(validateTextBoxInput)
			if selectedKeysItem<0:
				selectedKeysItem=0
		elif selectedKeysItem==1:
			appSKeyBox.edit(validateTextBoxInput)
			if selectedKeysItem==2:
				updateKeysWindow()
		elif selectedKeysItem==4:
			appKeyBox.edit(validateTextBoxInput)
		elif selectedKeysItem==5:
			devNonceBox.edit(validateTextBoxInput)
		elif selectedKeysItem==6:
			appNonceBox.edit(validateTextBoxInput)
		elif selectedKeysItem==7:
			netIDBox.edit(validateTextBoxInput)
		elif selectedKeysItem==8:
			devEUIBox.edit(validateTextBoxInput)
	keysWindow.refresh()

def updateSortWindow():
	global sortWindow, selectedSort
	i=0
	third=int(len(headers)/3)
	for h in headers:
		if i==selectedSort:
			sortWindow.attron(curses.A_REVERSE)
		else:
			sortWindow.attroff(curses.A_REVERSE)
		sortWindow.addstr(3+i%third,5+15*int(i/third),h[0])
		i=i+1
	sortWindow.refresh()

def populateTableData(startRow): #populate the table on startup and when scrolling

	l=0
	i=0
	for h in headers:
		if h[3]: # if column enabled
			if i==selectedSort:
				headerWindow.attron(curses.A_STANDOUT) # highlight the sorting column
			else:
				headerWindow.attroff(curses.A_STANDOUT)
			headerWindow.addstr(0,l+h[1]-len(h[0]),h[0]) #right align
			l=l+h[1]
		i=i+1
	headerWindow.refresh()
#	currentState=nodes.keys() #update later for sorting
	for i in range(0,bounds[0]-3):
#	tableWindows[i-1].addstr(n)
		tableWindows[i].erase() #need to clear the old data on update
		l=0
		if i<len(currentSorted): #account for the case for not enough nodes to fill the screen
			for h in headers:
				if h[3]: #is this column enabled?
					data=nodes[currentSorted[startRow+i]][h[2]] #the key for the node dictionary is stored in h field 2
					data=truncateColumn(data,h[1]) #length is in field 1
					l2=len(data)
					if not all(ord(c) < 128 for c in data): #ends in an elipses or is a check
						l2=l2-2 #The elipses counts as 2 characters, so gives the wrong value of len. We need to decrease the length value
					tableWindows[i].addstr(0,l+h[1]-l2, data) #right algin
					l=l+h[1]
		if len(nodes)>startRow+i and nodes[currentSorted[startRow+i]]["Issues"]!="":
			tableWindows[i].bkgd(curses.color_pair(ALERT))
		else:
			tableWindows[i].bkgd(curses.color_pair(DEFAULT))
		tableWindows[i].refresh()
		i=i+1
		headerWindow.redrawwin()

#first load any saved data
f=open('./keys.lst','r')
for lines in f.readlines():
	keys.append(lines.strip().split(",")) #load saved keys from old sessions
f.close()

for f in listdir(directory):
	if f.endswith(".csv"):
		with open(join(directory,f)) as csvfile:
			reader=csv.DictReader(csvfile)
			for row in reader:
				if(row['status']=="CRC_OK "):
					addPacket(row['payload'].replace("-",""), row['UTC timestamp'], row['datarate'], row['frequency'], row['RF chain'], row['RX chain'], row['coderate'], row['RSSI'], row['SNR'].strip())
#exit()
calculateNodeStats()
currentSorted=sorted(nodes, key=lambda x: nodes[x]["LastTime"],reverse=sortDirection)
stdscr=curses.initscr()
curses.start_color()
curses.curs_set(0)
curses.noecho()
curses.cbreak()
stdscr.keypad(1)
stdscr.box()
bounds=stdscr.getmaxyx()

tableWindows=[]
nodeWindows=[]
#do i need these? maybe to read them later?
appKeyBox=""
fcntBox=""
devNonceBox=""
appNonceBox=""
nwkSKeyBox=""
appSKeyBox=""
appKeyBox=""
devNonceBox=""
appNonceBox=""
netIDBox=""

#testwindow=curses.newwin(10,10,10,10)
#testwindow.refresh()
stdscr.refresh()

curses.init_pair(DEFAULT, curses.COLOR_WHITE, curses.COLOR_BLACK)
curses.init_pair(SELECTED, curses.COLOR_WHITE, curses.COLOR_BLUE)
curses.init_pair(HEADER, curses.COLOR_BLACK, curses.COLOR_WHITE)
curses.init_pair(MENU, curses.COLOR_RED, curses.COLOR_WHITE)
curses.init_pair(PACKETMENU, curses.COLOR_GREEN, curses.COLOR_BLACK)
curses.init_pair(ALERT, curses.COLOR_WHITE, curses.COLOR_MAGENTA)

for i in range(0,bounds[0]-3):
	tableWindows.append(curses.newwin(1,bounds[1]-2,i+2,1))
	if i>1: #2 more rows for the packet window
		nodeWindows.append(curses.newwin(1,bounds[1]-4,i+1,2))
#i+2 to leave room for the border and header

tableWindows[0].bkgd(curses.color_pair(SELECTED))

#the headers

headerWindow=curses.newwin(1,bounds[1]-2,1,1)
headerWindow.bkgd(curses.color_pair(HEADER))

packetHeaderWindow=curses.newwin(2, bounds[1]-4,2,2)
packetHeaderWindow.bkgd(curses.color_pair(HEADER))

#all the data starting at the beginning
populateTableData(0)

#The table in the top right

stdscr.move(0, bounds[1]-len(title)-1) 
stdscr.addstr(title)

#create the subwindows

sortWindow=curses.newwin(10, 50, int(bounds[0]/2-5), int(bounds[1]/2-25))
sortWindow.bkgd(curses.color_pair(MENU))
#sortWindow.attron(curses.A_BOLD)
sortWindow.box()
sortWindow.addstr(1,1,"Sort by:")

nodeWindow=curses.newwin(bounds[0]-2, bounds[1]-2,1,1)
nodeWindow.bkgd(curses.color_pair(PACKETMENU))
nodeWindow.box()
packetBounds=nodeWindow.getmaxyx()

keysWindow=curses.newwin(20, 50, int(bounds[0]/2-10), int(bounds[1]/2-25))
keysWindow.bkgd(curses.color_pair(MENU))
keysWindow.box()

#key window textboxes
appSKeyWin=keysWindow.derwin(1,33,4,15)
appSKeyWin.attron(curses.A_REVERSE)
appSKeyBox=curses.textpad.Textbox(appSKeyWin)
#appSKeyBox.attron(curses.A_REVERSE)
nwkSKeyWin=keysWindow.derwin(1,33,3,15)
nwkSKeyWin.attron(curses.A_REVERSE)
nwkSKeyBox=curses.textpad.Textbox(nwkSKeyWin)
#nwkSKeyBox.attron(curses.A_REVERSE)
appKeyWin=keysWindow.derwin(1,33,10,15)
appKeyWin.attron(curses.A_REVERSE)
appKeyBox=curses.textpad.Textbox(appKeyWin)
devNonceWin=keysWindow.derwin(1,3,11,15)
devNonceWin.attron(curses.A_REVERSE)
devNonceBox=curses.textpad.Textbox(devNonceWin)
appNonceWin=keysWindow.derwin(1,4,12,15)
appNonceWin.attron(curses.A_REVERSE)
appNonceBox=curses.textpad.Textbox(appNonceWin)
netIDWin=keysWindow.derwin(1,5,11,27)
netIDWin.attron(curses.A_REVERSE)
netIDBox=curses.textpad.Textbox(netIDWin)
devEUIWin=keysWindow.derwin(1,9,12,27)
devEUIWin.attron(curses.A_REVERSE)
devEUIBox=curses.textpad.Textbox(devEUIWin)
#the counter in the bottom right
indexString= str(scrollOffset+selectedLine+1)+"/"+str(len(nodes))
stdscr.move(bounds[0]-1, bounds[1]-len(indexString)-1)
stdscr.addstr(indexString)
stdscr.hline(bounds[0]-1, bounds[1]-10,curses.ACS_HLINE, 9-len(indexString))

doSecurityChecks()


while(True):

#update the display based on the window we have selected

	ch=stdscr.getch()
	if currentWindow==MAIN:
		processMainWindow(ch)
	elif currentWindow==SORT:
		processSortWindow(ch)
	elif currentWindow==PACKETS:
		processNodeWindow(ch)
	elif currentWindow==KEYS:
		processKeysWindow(ch)
	#the counter in the bottom right
	indexString= str(scrollOffset+selectedLine+1)+"/"+str(len(nodes))
	stdscr.move(bounds[0]-1, bounds[1]-len(indexString)-1)
	stdscr.addstr(indexString)
	stdscr.hline(bounds[0]-1, bounds[1]-10,curses.ACS_HLINE, 9-len(indexString))
	stdscr.refresh()
