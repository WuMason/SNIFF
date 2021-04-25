# SNIFF

SNIFF is a security auditing and social-engineering research tool.You can use it to find the MAC address of the IoT device on a wireless network.

## :book: How it works
* Scan for a target wireless network.
* Launch the Handshake Snooper.
* Find the MAC address of the IoT device.

## :scroll: Tools
You need some Software and Hardware tools!
| wireless network  | Device |
| ------------- | ------------- |
| WIFI  | Wireless network card(RTL8187 or RTL3037) and aircrack-ng  |
| Bluetooth  | Ubertooth One  |
| Zigbee  | TI CC 2531  |


## :heavy_exclamation_mark: Use

steps:
<br>
**Download the latest revision**
```
git clone git@github.com:WuMason/SNIFF.git

# Or if you prefer https 

git clone https://github.com/WuMason/SNIFF.git
```
**Switch to tool's directory**
```
cd SNIFF
```
**Run fluxion (missing dependencies will be auto-installed)**
```
./com_neldtv_sniff_iot.py
```
