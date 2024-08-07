from geoip2.database import Reader
import pandas as pd

class MapIPs:
    def __init__(self):
        self.geoip_data_path = 'lib/GeoLite2-City.mmdb'

    def ip_to_location(self, ip):
        try:
            with Reader(self.geoip_data_path) as reader:
                response = reader.city(ip)
                lat, lon = response.location.latitude, response.location.longitude
                return lat, lon
        except Exception as e:
            return None, None

    def generate_map_data(self, transaction_data):
        src_lats, src_lons, src_descriptions = [], [], []
        dst_lats, dst_lons, dst_descriptions = [], [], []
        unmapped_src_ip = None
        unmapped_ips = set()

        for flow in transaction_data['tcp_flows']:
            src_ip, dst_ip = flow['flow'][0][0], flow['flow'][1][0]  # Extract source and destination IPs

            src_lat, src_lon = self.ip_to_location(src_ip)
            dst_lat, dst_lon = self.ip_to_location(dst_ip)
            
            if src_lat is None or src_lon is None:
                unmapped_src_ip = src_ip  # Treat as the source IP (this might result in multiple source IPs because I'm using unmapped items. Need to find a better way)
                unmapped_ips.add(src_ip)
            else:
                src_lats.append(src_lat)
                src_lons.append(src_lon)
                src_descriptions.append(f"Source IP: {src_ip}")

            if dst_lat is None or dst_lon is None:
                unmapped_ips.add(dst_ip)
            else:
                dst_lats.append(dst_lat)
                dst_lons.append(dst_lon)
                dst_descriptions.append(f"Destination IP: {dst_ip}")

        if unmapped_src_ip:
            # Coordinates for the middle of the Pacific Ocean (didn't know where to put unmapped/source IPs, so figured middle of the ocean is best for visual clarity)
            src_lat, src_lon = 0.0, -160.0
            src_lats.append(src_lat)
            src_lons.append(src_lon)
            src_descriptions.append(f"Source IP: {unmapped_src_ip}")

        src_df = pd.DataFrame({'description': src_descriptions, 'lat': src_lats, 'lon': src_lons})
        dst_df = pd.DataFrame({'description': dst_descriptions, 'lat': dst_lats, 'lon': dst_lons})
        
        map_data = {
            "src": src_df.to_dict(orient='records'),
            "dst": dst_df.to_dict(orient='records'),
            "unmapped": list(unmapped_ips)
        }
        return map_data