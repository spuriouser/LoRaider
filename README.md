# LoRaider
A tool for analysing LoRaWAN packet captures

LoRaider reads csv files produced by the Semtech util_pkt_logger program (https://github.com/Lora-net/lora_gateway/tree/master/util_pkt_logger) that comes by default with many LoRaWAN setups. It pulls out key statistics for each packet and node and displays them in a more easily readable format. It also provides for easier sorting of data.

LoRaider is intended to be useful in performing security audits of LoRaWAN devices and deployments in making it easy to quickly identify anomalous or policy-violating behaviours. LoRaider checks for some basic trouble indicators (currently duplicate counters and variable length payloads) on start.

LoRaider features the ability to take a NwkSKey and AppSKey pair and identify whether any packets in the capture can be decrypted by these keys and produce the unencrypted payloads. The keys wil be saved for later use in keys.lst.

# Usage

* Clone the repository
* Configure a virtualenvironment according to the requirements.txt file
* Copy any packet captures into the local directory
* launch loraider.py under python 2.7

Within the app, the following key bindings are in place:

	q - quit
	s - Sort menu: select which column to sort the nodes by
	k - Keys menu: input keydata to decrypt packets
	enter / space: confirm selection; view individual packet data for the selected node
	
# Disclaimer

LoRaider is a project I've been working on in my spare time, for three primary reasons:
      
	1.) To learn more about python
	2.) To learn about ncurses
	3.) To learn about, and produce a reasonably useful tool for analysing, LoRaWAN.

It has certainly been successful in the first two goals, as I now know a bunch of things I would do differently if starting from scratch!

LoRaider is very, VERY much in the development phase right now. I've made it public now for some initial interested parties to have a look at it. There are a bunch of bugs and features I want to work in, including:
 * Generating NwkSKey and AppSKey pairs from JOIN packet data, with the capability to brute-force app and dev nonces if these are unknown.
 * Supporting more packt types
 * Supporting LoRaWAN 1.1
 * Being more clever about its display and re-scaling itself if the window is resized or is too small for the default view on startup
 * Decent documentation
 * Basic command line arguments (packet capture location)
 * Get around the current dependency on pycryptodome so that LoRaider will more readily run on ARM-based hardware suchas most LoRaWAN gateways tend to be.

