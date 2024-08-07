import dpkt, os, socket, json
from datetime import datetime
from dateutil import relativedelta

class SignatureGenerator:
    def __init__(self, pcapfile):
        self.pcapfile = pcapfile
        self.outputfile = "{}_{}.txt".format(
            pcapfile.rstrip('.pcap'), datetime.now().strftime("%Y%m%d-%H%M%S")
        )
        self.signature_file = "{}_{}.json".format(
            pcapfile.rstrip('.pcap'), datetime.now().strftime("%Y%m%d-%H%M%S")
        )
    
    def calculate_time_in_between(self, query_times):
        count = 0
        time_between_queries = []
        microseconds_in_between = []
        total_queries = len(query_times)
        while count < total_queries -1: # go thorugh times, matching the one time with the next to calculate the time between them
            firsttime = query_times[count]
            nexttime = query_times[count+1]        
            dt_firsttime=datetime.strptime(firsttime,'%d-%m-%Y %H:%M:%S:%f') # Convert string time to datetime
            dt_nexttime=datetime.strptime(nexttime,'%d-%m-%Y %H:%M:%S:%f') # Convert string time to datetime
            difference = relativedelta.relativedelta(dt_nexttime,dt_firsttime) # calculate difference in microseconds
            # other options: difference.microseconds, difference.seconds, difference.minutes, difference.hours, difference.days, difference.months, difference.years
            microseconds_in_between.append(difference.microseconds)
            count +=1
        return(total_queries,microseconds_in_between)

    def initial_processing(self, inputfile):
        query_times,date_times = [],[] # query_times hold time objects as strings, used in calculate_time_in_between{}. date_times hold datetime objects, used in plot_times_in_between_events()
        tflows,uflows = {},{}
        ips = set()
        # if b'\x00' in inputfile:
        #     raise ValueError("Null bytes are not allowed in the inputfile")
        f = open(inputfile,"rb")
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)   # will show everything since it's ethernet frames
            ip = eth.data # same as previous
            ### Get Flow data:
            try: # determine transport layer type
                if ip.p==dpkt.ip.IP_PROTO_TCP:
                    flows = tflows
                elif ip.p==dpkt.ip.IP_PROTO_UDP:
                    flows = uflows
            
                # extract IP and transport layer data
                src_ip = socket.inet_ntoa(ip.src)
                src_port = ip.data.sport
                dst_ip = socket.inet_ntoa(ip.dst)
                dst_port = ip.data.dport

                # keeping set of unique IPs
                ips.add(src_ip)
                ips.add(dst_ip)

                # store flow data
                flow = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                flow = (flow[0], flow[1])
                flow_data = {'byte_count': len(eth),'ts': ts}
                if flows.get(flow):
                    flows[flow].append(flow_data)
                else:
                    flows[flow] = [flow_data]

                try:
                    ip.get_proto(ip.p)
                    tcp = ip.data # will only print tcp data
                    data = tcp.data
                    dtstring=datetime.fromtimestamp(ts).strftime('%d-%m-%Y %H:%M:%S:%f') # Convert time to string
                    dt=datetime.strptime(dtstring,'%d-%m-%Y %H:%M:%S:%f') # Convert string time to datetime, used in plot_times_in_between_events
                    m = str(ts).split('.')[1]
                    try:    # get just HTTP packets
                        http = dpkt.http.Request(data)
                        method = http.method
                        uri = http.uri
                        destination_host = http.headers['host']
                        query_times.append(dtstring)
                        date_times.append(dt)
                    except:        
                        query_times.append(dtstring)
                        date_times.append(dt)
                except:
                    pass
            except:
                pass
        return(query_times)

    def get_average_time_in_between(self, microseconds):
        sum_of_queries = sum(microseconds)
        try:
            average_of_microseconds = sum_of_queries / len(microseconds)
            return(average_of_microseconds)
        except:
            return("ERROR","ERROR")

    def get_percentages(self, time_between_queries):
        percentages_of_times_in_between = []
        total_time_between_queries = sum(time_between_queries)
        for i in time_between_queries[:-1]:
            percent = (i/total_time_between_queries) * float(100)
            percentages_of_times_in_between.append(percent)
        return(percentages_of_times_in_between)

    def main(self, pcapfile):
        query_times = self.initial_processing(pcapfile)
        total_queries, microseconds_in_between = self.calculate_time_in_between(query_times)
        # average_time_in_between_queries = self.get_average_time_in_between(microseconds_in_between)
        percentages_of_times_in_between = self.get_percentages(microseconds_in_between)
        percentages_rounded = [round(item) for item in percentages_of_times_in_between] # how much the time in between the packet before and the next packet are a percentage of the total time of the TCP flow.
        percentages_rounded_with_no_zeros = [i for i in percentages_rounded if i != 0] # remove all the zeros to shrink down the results of the percentages
        return(percentages_rounded_with_no_zeros)

    def make_signature(self, percentages_rounded_with_no_zeros,signature_file):
        sig = {}
        sig[signature_file.rstrip('.json')] = percentages_rounded_with_no_zeros

        try:
            with open('signatures/networkrules/signatures.json', 'r') as infile: # open existing file if it exists:
                existing_data = json.load(infile)

            existing_data.update(sig) # Add the new dictionary item to the existing dictionary
            
            with open('signatures/networkrules/signatures.json', 'w') as outfile:
                json.dump(existing_data, outfile)
            return(existing_data)

        except:
            with open('signatures/networkrules/signatures.json', 'w') as outfile:
                json.dump(sig, outfile)