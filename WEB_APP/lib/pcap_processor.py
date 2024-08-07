import dpkt, os, subprocess, shutil, json, socket, subprocess
from datetime import datetime
from dateutil import relativedelta
from collections import Counter
import pendulum as pdl
from fuzzywuzzy import fuzz
from functools import reduce
from multiprocessing import Pool
from Levenshtein import distance as levenshtein_distance
from lib.map_processor import MapIPs
from elasticsearch import Elasticsearch

elasticsearch_host = 'YOUR ELASTICSEARCH HOST'
index_name = "pcap_sig_matches"
ntfy_url = "https://notify.YOURSERVER.com/server_alerts"

threshold = 62  # Adjust as needed
levenshtein_threshold = 17  # Adjust as needed

signature_file = 'signatures/networkrules/signatures.json'
pcap_directory = 'static/analysis/flowoutputs'

def send_to_ntfy_server(data):
    for match in data['matches']:
        message = f"Match found: {match['filename']} with signature {match['signature_name']} and ratio {match['ratio']}%"
        subprocess.run([
            'curl', '-X', 'POST', ntfy_url,
            '-d', message
        ])

def send_to_elasticsearch(data):
    es = Elasticsearch([{'host': elasticsearch_host, 'port': 9200, 'scheme': 'http'}])
    current_timestamp = datetime.utcnow().isoformat()
    
    for match in data['matches']:
        match['timestamp'] = current_timestamp
        es.index(index=index_name, body=match)

class PcapProcessor:
    def __init__(self):
        self.progress_file = 'progress.json'
        self.initialize_progress()

    def initialize_progress(self):
        if not os.path.exists(self.progress_file):
            self.update_progress(0)
            
    def update_progress(self, progress):
        with open(self.progress_file, 'w') as f:
            json.dump({'progress': progress}, f)

    def count_stuff(self, listofitems):
        return Counter(listofitems)

    def dumpFlow(self, flows, flow):
        bytes = reduce(lambda x, y: x + y, map(lambda e: e['byte_count'], flows[flow]))
        duration = sorted(map(lambda e: e['ts'], flows[flow]))
        duration = duration[-1] - duration[0]
        return {
            "flow": flow,
            "total_bytes": bytes,
            "average_bytes": bytes / len(flows[flow]),
            "total_duration": duration,
            "flow_data": flows[flow]  # flow_data for the entire PCAP is used in the mapping function
        }

    def get_transactions(self, pcapfile):
        tflows = {}
        uflows = {}
        ips = set()
        with open(pcapfile, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, pkt in pcap:
                eth = dpkt.ethernet.Ethernet(pkt)
                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    ip = eth.data
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        flows = tflows
                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        flows = uflows
                    src_ip = socket.inet_ntoa(ip.src)
                    src_port = ip.data.sport
                    dst_ip = socket.inet_ntoa(ip.dst)
                    dst_port = ip.data.dport
                    ips.add(src_ip)
                    ips.add(dst_ip)
                    flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                    flow = (flow[0], flow[1])
                    flow_data = {
                        'byte_count': len(eth),
                        'ts': ts,
                        'src_ip': src_ip,
                        'dst_ip': dst_ip
                    }
                    if flows.get(flow):
                        flows[flow].append(flow_data)
                    else:
                        flows[flow] = [flow_data]
        transaction_data = {
            "total_tcp_flows": len(tflows.keys()),
            "total_udp_flows": len(uflows.keys()),
            "total_ips": len(ips),
            "tcp_flows": [self.dumpFlow(tflows, k) for k in tflows.keys()],
            "udp_flows": [self.dumpFlow(uflows, k) for k in uflows.keys()]
        }
        return transaction_data

    def calculate_time_in_between(self, query_times):
        time_between_queries = []
        microseconds_in_between = []
        total_queries = len(query_times)
        for count in range(total_queries - 1):
            firsttime = query_times[count]
            nexttime = query_times[count + 1]
            dt_firsttime = datetime.strptime(firsttime, '%d-%m-%Y %H:%M:%S:%f')
            dt_nexttime = datetime.strptime(nexttime, '%d-%m-%Y %H:%M:%S:%f')
            difference = relativedelta.relativedelta(dt_nexttime, dt_firsttime)
            time_between_queries.append({
                "difference_in_microseconds": difference.microseconds,
                "first_time": dt_firsttime.time().isoformat(),
                "next_time": dt_nexttime.time().isoformat()
            })
            microseconds_in_between.append(difference.microseconds)
        return total_queries, time_between_queries, microseconds_in_between

    def initial_processing(self, inputfile):
        query_times, date_times = [], []
        with open(inputfile, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    dtstring = datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S:%f')
                    dt = datetime.strptime(dtstring, '%d-%m-%Y %H:%M:%S:%f')
                    query_times.append(dtstring)
                    date_times.append(dt)
                except Exception as e:
                    print(f"Error processing packet: {e}")
                    continue
        return date_times, query_times

    def process_transaction_times(self, microseconds_in_between, datedom_cnt):
        start_time = pdl.datetime(2000, 1, 1, 0, 0, 0, 0)  # normalize the date by getting rid of the real date. All traffic begins at the same time
        when_transactions_happened = []
        for i in datedom_cnt:
            item = {}
            microseconds = int(datetime.strptime(str(i[0]), '%Y-%m-%d %H:%M:%S.%f').strftime('%f'))
            when_there_were_transactions = pdl.datetime(2000, 1, 1, 0, 0, 0, microseconds)
            item['date'] = when_there_were_transactions
            item['count'] = i[1]
            when_transactions_happened.append(item)

        full_timeline_from_zero = [start_time]
        time_point = start_time
        for t in microseconds_in_between:
            time_point = time_point.add(microseconds=t)
            full_timeline_from_zero.append(time_point)

        percentages_of_times_in_between = self.get_percentages(microseconds_in_between)
        percentages_rounded = [round(item) for item in percentages_of_times_in_between]
        percentages_rounded_with_no_zeros = [i for i in percentages_rounded if i != 0]

        return {
            "when_transactions_happened": when_transactions_happened,
            "full_timeline_from_zero": full_timeline_from_zero,
            "percentages_rounded": percentages_rounded_with_no_zeros
        }

    def get_percentages(self, time_between_queries):
        total_time_between_queries = sum(time_between_queries)
        percentages_of_times_in_between = [
            (i / total_time_between_queries) * 100 for i in time_between_queries[:-1]
        ]
        return percentages_of_times_in_between

    def process_stream(self, args):
        inputfile, stream, pcap_directory, total_streams, index = args
        try:
            tshark_cmd = f"tshark -r {inputfile} -w {pcap_directory}/stream-{stream}.pcap -Y \"tcp.stream=={stream}\""
            editcap_cmd = f"editcap -F libpcap -T ether {pcap_directory}/stream-{stream}.pcap {pcap_directory}/{inputfile.rstrip('.pcap').split('upload/')[1]}_{stream}.pcap"
            rm_cmd = f"rm {pcap_directory}/stream-{stream}.pcap"
            
            subprocess.check_output(tshark_cmd, shell=True)
            subprocess.check_output(editcap_cmd, shell=True)
            subprocess.check_output(rm_cmd, shell=True)
            
            # Calculate progress (this is for the progress bar in the web app)
            progress = int(((index + 1) / total_streams) * 100)
            self.update_progress(progress)
        except subprocess.CalledProcessError as e:
            print(f"Error processing stream {stream}: {e}")
            
    def start(self, inputfile):
        try:
            shutil.rmtree(pcap_directory)
        except Exception as e:
            print(f"Error removing directory: {e}")
        os.makedirs(pcap_directory)
        
        streams = subprocess.check_output(f"tshark -r {inputfile} -T fields -e tcp.stream | sort -n | uniq", shell=True).decode().split()  # Get the total number of streams
        total_streams = len(streams)
        self.update_progress(0)
        args = [(inputfile, stream, pcap_directory, total_streams, index) for index, stream in enumerate(streams)]  # Prepare arguments for parallel processing
        with Pool() as pool:  # Use multiprocessing to process streams in parallel
            pool.map(self.process_stream, args)

        potential_matches = []
        for file in os.listdir(pcap_directory):
            if file.endswith(".pcap"):
                pcapfile = os.path.join(pcap_directory, file)
                date_times, query_times = self.initial_processing(pcapfile)
                total_queries, time_between_queries, microseconds_in_between = self.calculate_time_in_between(query_times)
                counted = self.count_stuff(date_times)
                datedom_cnt = counted.items()
                processed_transaction_times = self.process_transaction_times(microseconds_in_between, datedom_cnt)
                potential_match = {
                    "filename": pcapfile,
                    "when_transactions_happened": processed_transaction_times['when_transactions_happened'],
                    "full_timeline_from_zero": processed_transaction_times['full_timeline_from_zero'],
                    "percent_of_times_in_between": processed_transaction_times['percentages_rounded']
                }
                potential_matches.append(potential_match)

        transaction_data = self.get_transactions(inputfile)  # Generate transaction data
        map_processor = MapIPs()  # Create a new instance of MapIPs for each process
        map_data = map_processor.generate_map_data(transaction_data)  # Generate map data

        with open(signature_file) as f:
            sigs = json.load(f)
        signatures = [{"signature_name": k, "signature": v} for k, v in sigs.items()]
        results = []
        unmatched = []
        for m in potential_matches:
            match_results = []
            for s in signatures:
                partial_ratio = fuzz.partial_ratio(s['signature'], m['percent_of_times_in_between'])
                levenshtein_dist = levenshtein_distance("".join(map(str, s['signature'])), "".join(map(str, m['percent_of_times_in_between'])))
                if partial_ratio >= threshold and levenshtein_dist <= levenshtein_threshold:
                    match_results.append({
                        "filename": m['filename'],
                        "signature_name": s['signature_name'],
                        "ratio": partial_ratio,
                        "levenshtein_distance": levenshtein_dist,
                        "signature_percentages": s['signature'] if m['percent_of_times_in_between'] == s['signature'] else None
                    })
            if match_results:
                results.extend(match_results)
            else:
                unmatched.append({
                    "filename": m['filename'],
                    "ratio": max([fuzz.partial_ratio(s['signature'], m['percent_of_times_in_between']) for s in signatures]),
                    "levenshtein_distance": min([levenshtein_distance("".join(map(str, s['signature'])), "".join(map(str, m['percent_of_times_in_between']))) for s in signatures])
                })

        final_results = {"matches": results, "unmatched": unmatched, "map_data": map_data}  # Include map data in final results

        # Send matching results to Elasticsearch and ntfy server

        if final_results['matches']:
            try:
                send_to_elasticsearch(final_results)
            except Exception as e:
                print("Failed to send results to Elasticsearch")
            try:
                send_to_ntfy_server(final_results)
            except:
                print("Failed to send to ntfy server")

        self.update_progress(100)
        return json.dumps(final_results)