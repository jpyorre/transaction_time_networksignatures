import os, tempfile, shutil, subprocess, yara, platform

if platform.system() == 'Darwin':  
    tcpFlowPath = "/opt/homebrew/bin/tcpflow" # OSX - adjust this path based on your OSX setup
elif platform.system() == 'Linux':
    tcpFlowPath = "/usr/bin/tcpflow"  # Linux - adjust this path based on your Linux setup
else:
    raise EnvironmentError("Unsupported operating system")

class YaraPcapProcessor:
    def __init__(self, pcap, rules):
        self.pcap = pcap
        self.rules = rules

    def process_pcap(self, tmpDir):
        shutil.copyfile(self.pcap, os.path.join(tmpDir, "raw.pcap"))
        retcode = subprocess.call(f"(cd {tmpDir} && {tcpFlowPath} -a -r raw.pcap)", shell=True)
        if retcode != 0:
            raise subprocess.CalledProcessError(retcode, tcpFlowPath)
        return tmpDir

    def yara_scan(self, scanfile, yara_rules):
        matches = []
        if os.path.getsize(scanfile) > 0:
            for match in yara_rules.match(scanfile):
                matches.append({"name": match.rule, "meta": match.meta})
        return matches

    def main(self):
        tmpDir = tempfile.mkdtemp()
        try:
            self.process_pcap(tmpDir)
            yara_rules = yara.compile(self.rules)
            results_uniqued = []
            for httpReq in os.listdir(tmpDir):
                results = self.yara_scan(os.path.join(tmpDir, httpReq), yara_rules)
                if results:
                    for item in results:
                        line = "Signature Name: {}</br>Author: {}</br>Date: {}".format(item['name'], item['meta']['author'], item['meta']['date'])
                        results_uniqued.append(line)
            return results_uniqued
        finally:
            shutil.rmtree(tmpDir)
