This is a web/API application that demonstrates research I am working on involving identifying malicious network traffic based on the time differences between network packet transactions.

[Slides](https://pyosec.com/presentations/joshpyorre_signature_based_detection_using_network_timing.pdf)

![screenshot of the app](example.png?raw=true)

## Architecture:

This was built on an OSX system running Sonoma 14.5, although some development has been done on Linux. The architecture won't matter as it's all Python, but installing some dependencies, such as YARA might have differences.

Python/PIP Versions used:
- Python 3.11.4
- pip 24.2 

## Setup:

Download repository:
`git clone https://github.com/jpyorre/transaction_time_networksignatures`

Install requirements:
`pip install -r requirements.txt`

### OSX-specific items:

tcpflow:

```
brew install tcpflow
```

YARA:

```
brew install yara
pip install yara-python
```

tshark:

```
brew install wireshark
```

To use the mapping functionality, where it maps the source and destination IP's of all the flows in the PCAP you upload, you'll need to download the GeoLite2-City.mmdb from maxmind.

1. Create an account at https://dev.maxmind.com
2. Subscribe to a product (it's free and doesn't require a payment)
3. Download the file you need. *More info: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data*
4. Put the GeoLite2-City.mmdb in the `lib` folder

### Configuration variables:

When you make a rule based off a flow of network traffic (see Create network signatures section below), you may have to tune the thresholds as listed in the following lines at the top of lib/pcap_processor.py:

```
threshold = 62  # Adjust this value as needed
levenshtein_threshold = 4  # Adjust this value as needed
```

Future changes to thresholds: Dynamically change the threshold, depending on what kind of data is in the PCAP or via a variable set by the user in the web application or API client code.

### Elasticsearch:

*Elasticsearch is sent using a try/except at the bottom of lib/pcap_processor.py script, so if you haven't set it up, things will still work*

If you want to have results sent to Elasticsearch, you'll have to set it up and adjust the host at the top of lib/pcap_processor.py accordingly.

`elasticsearch_host = 'YOUR ELASTICSEARCH HOST'`

Below that is the following:
`index_name = "pcap_sig_matches"`
Either create an Elasticsearch index with that name or name it something else and adjust the variable name.

### ntfy:

*ntfy is sent using a try/except at the bottom of lib/pcap_processor.py script, so if you haven't set it up, things will still work*

ntfy is a system you can use to get notifications of any kind. I set up my own server and have the client on my phone, allowing me to get notifications when there are signature matches. If you use this or want to use it, update the following with your server:
`ntfy_url = "https://notify.YOURSERVER.com/server_alerts"`

# Using the web application/API:

This runs as a Fastapi server, wrapped in a flask web app. You an upload one PCAP at a time to check against signatures you've created with other PCAP files. It also runs as an API. You can send PCAP files to it continuously via a client-side script and have it process through them.

## Start the app:

Open a terminal, change to the root directory of WEB_APP, and run with:

`uvicorn app:app --reload`

then visit http://127.0.0.1:8000 in a browser.

## Menu Items:

There are three menu items: 
- YARA PCAP
- Signatures
- Analyze PCAP.

### YARA PCAP:

This was created as a proof of concept to run YARA rules against PCAP's. If you want to add a YARA rule, make one in the `signatures` > `yararules` directory, then upload a PCAP to see if there's a match.

### Signatures:

- Create a PCAP file that contains isolated network activity you are interested in finding in other PCAP files.
- Upload that isolated PCAP file on the `signatures` page. 
- This calculates the milliseconds between network transactions, rounded up or down, and converts to a percentage of the total time of all the times in between every transaction. All zero's have been removed and some other processing has occurred to make the lists of numbers small.
- Signatures are displayed on this page. After you create one, you'll see it in the list.

#### Finding and preparing PCAPs to make signatures from

https://malware-traffic-analysis.net/ is the main source I used to get known-malicious PCAP files to make into signatures.
The following script: `UTILITIES/unzip_mta_files.py`  can be used to automatically unzip any PCAP zip files you download into the same directory as `unzip_mta_files.py`. It looks for zip files, grabs the date from the name of the file and uses it along with the rest of the malware-traffic-analysis password scheme to automatically unzip them, leaving the PCAP files.

**After you have a PCAP you want to make a signature from:**

1. Open it in Wireshark. 
2. Find something you're interested in finding in other network traffic, such as a GET,  POST, or other known bad traffic.
3. Right-click on the item you're interested and select 'follow tcp stream' or 'follow http stream.
4. Using the Wireshark menu, click *File > Export Specified Packets*
5. In the dialogue box that appears, type a name, pick your location, check that the *Displayed* radio button is selected to get only the packets you've isolated, and click *Save*.
6. In the web app, go to *Signatures* and upload the just saved file to make a signature. The signature will be a list of numbers added to the *signatures > networkrules > signatures.json* file. You can add as many as you want. 

### Analyze PCAP:

- Upload any PCAP to the *analyzepcap* page that you think might contain network traffic similar to what is in the PCAP from which the signature was created. It can have other traffic within (there's no need to open it and isolate the traffic - the purpose of this tool is to find it for you). 

- If you have network data with the exact same malicious traffic from the signature, you will get a match of '100'. However, the idea is that malware variants of the same family tend to follow the same kinds of patterns. If the signature is from a version of ransomware from a month ago, running a PCAP through the system that contains more recent network traffic from that same ransomware family may result in a match. It wouldn't be 100 (the score), but would more likely be above 70 (this is where the threshold values come in)

- The score is created in the same way as the signature. Each flow in the PCAP file is separated and analyzed, producing the same list of microseconds in between transactions. Then, a search using Levenshtein distance is applied against any signatures to see how close the list of microseconds are to the list within each saved signature. Numbers of 70 or above often match fairly well, although this can be adjusted in `./lib/pcap_processor.py`, as mentioned at the top of this readme. `

- If there is a match, it will be displayed on the same page.

## API:

If you have a system that is set up to capture packets, saving them to disk for a short time, you can set up a process to send new files to the API, collecting the results in a database. The API can be running on the packet capture system or on another system. I recommend another system since the multiprocessing might conflict with packet captures. 

In my presentation, this process is demonstrated using Daemonlogger to automatically spool packets to disk, then writing matches to Elasticsearch for analysis and alerting. I also demonstrate sending notifications to the ntfy service as a way to get real-time alerts.

The file `utilities/client_pcap_submitter.py` shows how to use the API. 

#### Processing speed: 

- Any size PCAP can be uploaded, but it will increase the time it takes to process separating the flows. To speed this up, `pcap_processor.py` uses multiprocessing. The faster your computer, the faster it will go. A *not quite perfect yet* progress bar will be displayed as it runs through all the flows.

### Future plans:

- Recreate in Rust for faster processing
- Dynamic threshold management
- More UI improvement
- More Optimization
- PCAP Signature carving/creation without having to use Wireshark

## Other things:

### Creating a custom PCAP for testing:

If you want to take a known bad network capture and combine it with benign traffic before testing it with the application, you could use the *mergecap* tool to combine files. One file could be random traffic and the other file could be something downloaded from [malware-traffic-analysis.net](https://malware-traffic-analysis.net/) that contains malware network activity similar to a malware variant you have created a signature for. 

#### Instructions for OSX:

1. Install the command line version of wireshark.
	`brew install wireshark`
2. Combine two PCAP files:
	`mergecap -w combined.pcap file1.pcap file2.pcap`

If you want to rewrite the IP addresses or MAC addresses, use tcprewrite. Install with:
`brew install tcpreplay` (this installs tcpreplay and tcprewrite)

To then modify the MAC addresses, you could use something like:
`tcprewrite --dlt enet --enet-dmac=00:11:22:33:44:55 --enet-smac=66:77:88:99:AA:BB -i combined.pcap -o rewritten_combined.pcap`

Or modify the IP addresses:

`tcprewrite --infile=input.pcap --outfile=output.pcap --srcipmap=old_src_ip:new_src_ip --dstipmap=old_dst_ip:new_dst_ip`