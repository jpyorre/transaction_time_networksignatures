import requests
from pprint import pprint as pp
import sys

pcapfile = sys.argv[1]

def submit_pcap_file(file_path):
    url = "http://localhost:8000/analyze_pcap"
    files = {'file': open(file_path, 'rb')}
    
    response = requests.post(url, files=files)
    
    if response.status_code == 200:
        print("File submitted successfully!")
        print("Response:")
        pp(response.json())
    else:
        print(f"Failed to submit file. Status code: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    submit_pcap_file(pcapfile)