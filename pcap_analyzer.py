#!/usr/bin/env python3
"""
PCAP Traffic Analyzer
Analyzes PCAP files and extracts traffic by protocol (DNS, HTTP, ICMP, etc.)
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import statistics

try:
    import scapy.all as scapy
    from scapy.layers.inet import IP, ICMP, TCP, UDP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    from scapy.layers.l2 import Ether
except ImportError:
    print("Error: scapy library not found. Please install it with: pip install scapy")
    sys.exit(1)


class PCAPAnalyzer:
    """Main class for analyzing PCAP files and extracting protocol-specific traffic."""
    
    def __init__(self, pcap_file: str, verbose: bool = False):
        self.pcap_file = pcap_file
        self.verbose = verbose
        self.results = {
            'dns': [],
            'http': [],
            'https': [],
            'icmp': [],
            'tcp': [],
            'udp': [],
            'other': [],
            'summary': {},
            'advanced_analysis': {
                'connection_issues': [],
                'latency_issues': [],
                'https_errors': [],
                'dns_issues': [],
                'retry_patterns': [],
                'timeout_issues': [],
                'blocked_connections': [],
                'http_errors': [],
                'server_errors': [],
                'client_errors': [],
                'redirect_issues': [],
                'tls_issues': [],
                'smtp_issues': [],
                'ftp_issues': [],
                'smb_issues': [],
                'performance_metrics': [],
                'bandwidth_analysis': [],
                'packet_loss': [],
                'jitter_analysis': [],
                'security_issues': [],
                'port_scanning': [],
                'rapid_connections': [],
                'suspicious_patterns': [],
                'anomaly_detection': []
            }
        }
        self.stats = defaultdict(int)
        self.connections = {}  # Track TCP connections
        self.timing_data = []  # Store timing information
        self.dns_queries = {}  # Track DNS query-response pairs
        self.ip_addresses = set()  # Track all IP addresses
        self.latency_packets = []  # Track packets affected by latency
        
    def analyze_pcap(self) -> Dict[str, Any]:
        """Main method to analyze the PCAP/PCAPNG file."""
        print(f"Analyzing PCAP/PCAPNG file: {self.pcap_file}")
        
        try:
            # Read the PCAP/PCAPNG file (scapy handles both formats automatically)
            packets = scapy.rdpcap(self.pcap_file)
            print(f"Loaded {len(packets)} packets")
            
            if self.verbose:
                print("Processing packets...")
            
            for i, packet in enumerate(packets):
                if self.verbose and i % 100 == 0:
                    print(f"  Processed {i}/{len(packets)} packets...")
                self._analyze_packet(packet)
            
            if self.verbose:
                print(f"Completed processing {len(packets)} packets")
                
            # Perform advanced analysis after all packets are processed
            self._perform_advanced_analysis()
            self._generate_summary()
            return self.results
            
        except Exception as e:
            print(f"Error analyzing PCAP/PCAPNG file: {e}")
            return {}
    
    def _analyze_packet(self, packet):
        """Analyze individual packet and categorize by protocol."""
        try:
            self.stats['total_packets'] += 1
            
            # Store timing data for latency analysis
            self.timing_data.append(packet.time)
            
            # Extract basic packet info
            packet_info = {
                'timestamp': datetime.fromtimestamp(packet.time).isoformat(),
                'time': packet.time,
                'size': len(packet),
                'src_ip': None,
                'dst_ip': None,
                'src_port': None,
                'dst_port': None,
                'protocol': None
            }
        except Exception as e:
            # Skip problematic packets
            return
        
        # Extract IP layer info
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            packet_info['src_ip'] = ip_layer.src
            packet_info['dst_ip'] = ip_layer.dst
            packet_info['protocol'] = ip_layer.proto
            
            # Track IP addresses for classification
            self.ip_addresses.add(ip_layer.src)
            self.ip_addresses.add(ip_layer.dst)
            
        # Track TCP connections for advanced analysis
        if packet.haslayer(TCP):
            self._track_tcp_connection(packet, packet_info)
        
        # Track DNS queries for timing analysis
        if packet.haslayer(DNS):
            self._track_dns_query(packet, packet_info)
        
        # Analyze by protocol
        try:
            if packet.haslayer(DNS):
                self._analyze_dns(packet, packet_info)
            elif packet.haslayer(HTTP) or packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                self._analyze_http(packet, packet_info)
            elif packet.haslayer(ICMP):
                self._analyze_icmp(packet, packet_info)
            elif packet.haslayer(TCP):
                self._analyze_tcp(packet, packet_info)
            elif packet.haslayer(UDP):
                self._analyze_udp(packet, packet_info)
            else:
                self.results['other'].append(packet_info)
                self.stats['other'] += 1
        except Exception as e:
            # Skip problematic packets but still count them
            self.results['other'].append(packet_info)
            self.stats['other'] += 1
    
    def _analyze_dns(self, packet, packet_info):
        """Analyze DNS packets."""
        dns_layer = packet[DNS]
        
        dns_info = packet_info.copy()
        dns_info.update({
            'dns_id': dns_layer.id,
            'dns_qr': dns_layer.qr,  # 0 = query, 1 = response
            'dns_opcode': dns_layer.opcode,
            'dns_rcode': dns_layer.rcode if hasattr(dns_layer, 'rcode') else None,
            'questions': [],
            'answers': []
        })
        
        # Extract DNS questions
        if dns_layer.qd:
            for q in dns_layer.qd:
                try:
                    question = {
                        'qname': q.qname.decode() if isinstance(q.qname, bytes) else str(q.qname),
                        'qtype': getattr(q, 'qtype', 1),  # Default to A record
                        'qclass': getattr(q, 'qclass', 1)  # Default to IN class
                    }
                    dns_info['questions'].append(question)
                except AttributeError:
                    # Skip problematic DNS questions
                    pass
        
        # Extract DNS answers
        if dns_layer.an:
            for rr in dns_layer.an:
                try:
                    answer = {
                        'name': rr.rrname.decode() if isinstance(rr.rrname, bytes) else str(rr.rrname),
                        'type': getattr(rr, 'rrtype', getattr(rr, 'type', 'Unknown')),
                        'rdata': rr.rdata.decode() if isinstance(rr.rdata, bytes) else str(rr.rdata),
                        'ttl': getattr(rr, 'ttl', 0)
                    }
                    dns_info['answers'].append(answer)
                except AttributeError as e:
                    # Handle cases where DNS record attributes might not exist
                    answer = {
                        'name': str(getattr(rr, 'rrname', 'Unknown')),
                        'type': 'Unknown',
                        'rdata': str(getattr(rr, 'rdata', 'Unknown')),
                        'ttl': 0
                    }
                    dns_info['answers'].append(answer)
        
        self.results['dns'].append(dns_info)
        self.stats['dns'] += 1
    
    def _analyze_http(self, packet, packet_info):
        """Analyze HTTP packets."""
        http_info = packet_info.copy()
        
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            http_info.update({
                'method': req.Method.decode() if isinstance(req.Method, bytes) else str(req.Method),
                'path': req.Path.decode() if isinstance(req.Path, bytes) else str(req.Path),
                'host': req.Host.decode() if isinstance(req.Host, bytes) else str(req.Host),
                'user_agent': req.User_Agent.decode() if isinstance(req.User_Agent, bytes) else str(req.User_Agent),
                'packet_type': 'request'
            })
        elif packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            http_info.update({
                'status_code': resp.Status_Code.decode() if isinstance(resp.Status_Code, bytes) else str(resp.Status_Code),
                'reason_phrase': resp.Reason_Phrase.decode() if isinstance(resp.Reason_Phrase, bytes) else str(resp.Reason_Phrase),
                'packet_type': 'response'
            })
        
        # Determine if HTTPS based on port
        if packet_info.get('dst_port') == 443 or packet_info.get('src_port') == 443:
            self.results['https'].append(http_info)
            self.stats['https'] += 1
        else:
            self.results['http'].append(http_info)
            self.stats['http'] += 1
    
    def _analyze_icmp(self, packet, packet_info):
        """Analyze ICMP packets."""
        icmp_layer = packet[ICMP]
        
        icmp_info = packet_info.copy()
        icmp_info.update({
            'icmp_type': icmp_layer.type,
            'icmp_code': icmp_layer.code,
            'icmp_id': icmp_layer.id if hasattr(icmp_layer, 'id') else None,
            'icmp_seq': icmp_layer.seq if hasattr(icmp_layer, 'seq') else None
        })
        
        self.results['icmp'].append(icmp_info)
        self.stats['icmp'] += 1
    
    def _analyze_tcp(self, packet, packet_info):
        """Analyze TCP packets."""
        tcp_layer = packet[TCP]
        
        tcp_info = packet_info.copy()
        tcp_info.update({
            'src_port': tcp_layer.sport,
            'dst_port': tcp_layer.dport,
            'seq': tcp_layer.seq,
            'ack': tcp_layer.ack,
            'flags': {
                'FIN': tcp_layer.flags.F,
                'SYN': tcp_layer.flags.S,
                'RST': tcp_layer.flags.R,
                'PSH': tcp_layer.flags.P,
                'ACK': tcp_layer.flags.A,
                'URG': tcp_layer.flags.U
            },
            'window_size': tcp_layer.window,
            'payload_size': len(tcp_layer.payload) if tcp_layer.payload else 0
        })
        
        self.results['tcp'].append(tcp_info)
        self.stats['tcp'] += 1
    
    def _analyze_udp(self, packet, packet_info):
        """Analyze UDP packets."""
        udp_layer = packet[UDP]
        
        udp_info = packet_info.copy()
        udp_info.update({
            'src_port': udp_layer.sport,
            'dst_port': udp_layer.dport,
            'length': udp_layer.len,
            'checksum': udp_layer.chksum,
            'payload_size': len(udp_layer.payload) if udp_layer.payload else 0
        })
        
        self.results['udp'].append(udp_info)
        self.stats['udp'] += 1
    
    def _track_tcp_connection(self, packet, packet_info):
        """Track TCP connections for advanced analysis."""
        tcp_layer = packet[TCP]
        conn_id = f"{packet_info['src_ip']}:{tcp_layer.sport}-{packet_info['dst_ip']}:{tcp_layer.dport}"
        
        if conn_id not in self.connections:
            self.connections[conn_id] = {
                'src_ip': packet_info['src_ip'],
                'dst_ip': packet_info['dst_ip'],
                'src_port': tcp_layer.sport,
                'dst_port': tcp_layer.dport,
                'established': False,
                'packets': [],
                'start_time': packet_info['time'],
                'end_time': packet_info['time']
            }
        
        # Update connection data
        conn_data = self.connections[conn_id]
        conn_data['packets'].append(packet_info)
        conn_data['end_time'] = packet_info['time']
        conn_data['duration'] = conn_data['end_time'] - conn_data['start_time']
        
        # Check for connection establishment (SYN-ACK)
        if tcp_layer.flags.S and tcp_layer.flags.A:
            conn_data['established'] = True
    
    def _track_dns_query(self, packet, packet_info):
        """Track DNS queries for timing analysis."""
        try:
            dns_layer = packet[DNS]
            query_id = dns_layer.id
            
            if dns_layer.qr == 0:  # DNS Query
                if dns_layer.qd:
                    domain = dns_layer.qd[0].qname.decode() if isinstance(dns_layer.qd[0].qname, bytes) else str(dns_layer.qd[0].qname)
                    query_type = getattr(dns_layer.qd[0], 'qtype', 1)  # Default to A record
                    self.dns_queries[query_id] = {
                        'domain': domain,
                        'query_type': query_type,
                        'src_ip': packet_info['src_ip'],
                        'dst_ip': packet_info['dst_ip'],
                        'query_time': packet_info['time'],
                        'response_received': False
                    }
            elif dns_layer.qr == 1:  # DNS Response
                if query_id in self.dns_queries:
                    response_time = packet_info['time'] - self.dns_queries[query_id]['query_time']
                    self.dns_queries[query_id]['response_received'] = True
                    self.dns_queries[query_id]['response_time'] = response_time
        except (AttributeError, IndexError) as e:
            # Skip problematic DNS packets
            pass
    
    def _perform_advanced_analysis(self):
        """Perform advanced network analysis to detect issues."""
        if self.verbose:
            print("Performing advanced network analysis...")
        
        # Analyze TCP connections
        if self.verbose:
            print("  Analyzing TCP connections...")
        self._analyze_tcp_connections()
        
        # Analyze DNS timing and failures
        if self.verbose:
            print("  Analyzing DNS issues...")
        self._analyze_dns_issues()
        
        # Analyze HTTPS/SSL issues
        if self.verbose:
            print("  Analyzing HTTPS/SSL issues...")
        self._analyze_https_issues()
        
        # Analyze latency patterns
        if self.verbose:
            print("  Analyzing latency patterns...")
        self._analyze_latency_issues()
        
        # Detect retry patterns
        if self.verbose:
            print("  Detecting retry patterns...")
        self._detect_retry_patterns()
        
        # Analyze connection blocks
        if self.verbose:
            print("  Analyzing connection blocks...")
        self._analyze_connection_blocks()
        
        # Analyze HTTP errors and issues
        if self.verbose:
            print("  Analyzing HTTP errors...")
        self._analyze_http_errors()
        
        # Classify IP addresses
        if self.verbose:
            print("  Classifying IP addresses...")
        self._classify_ip_addresses()
        
        # Analyze protocol deep dive
        if self.verbose:
            print("  Analyzing protocol deep dive...")
        self._analyze_protocol_deep_dive()
        
        # Analyze performance metrics
        if self.verbose:
            print("  Analyzing performance metrics...")
        self._analyze_performance_metrics()
        
        # Analyze security issues
        if self.verbose:
            print("  Analyzing security issues...")
        self._analyze_security_issues()
        
        if self.verbose:
            print("Advanced analysis completed!")
    
    def _analyze_tcp_connections(self):
        """Analyze TCP connection states and issues."""
        for conn_id, conn_data in self.connections.items():
            if not conn_data.get('established', False):
                # Connection never established
                self.results['advanced_analysis']['connection_issues'].append({
                    'type': 'failed_connection',
                    'connection_id': conn_id,
                    'src_ip': conn_data.get('src_ip'),
                    'dst_ip': conn_data.get('dst_ip'),
                    'dst_port': conn_data.get('dst_port'),
                    'issue': 'Connection never established',
                    'packets': len(conn_data.get('packets', [])),
                    'duration': conn_data.get('duration', 0)
                })
            
            # Check for RST packets (connection resets)
            rst_packets = [p for p in conn_data.get('packets', []) if p.get('flags', {}).get('RST', False)]
            if rst_packets:
                self.results['advanced_analysis']['connection_issues'].append({
                    'type': 'connection_reset',
                    'connection_id': conn_id,
                    'src_ip': conn_data.get('src_ip'),
                    'dst_ip': conn_data.get('dst_ip'),
                    'dst_port': conn_data.get('dst_port'),
                    'issue': f'Connection reset by {len(rst_packets)} RST packets',
                    'rst_packets': len(rst_packets)
                })
    
    def _analyze_dns_issues(self):
        """Analyze DNS query-response timing and failures."""
        for query_id, query_data in self.dns_queries.items():
            if not query_data.get('response_received', False):
                # DNS query without response
                self.results['advanced_analysis']['dns_issues'].append({
                    'type': 'dns_timeout',
                    'query_id': query_id,
                    'domain': query_data.get('domain'),
                    'query_type': query_data.get('query_type'),
                    'src_ip': query_data.get('src_ip'),
                    'dst_ip': query_data.get('dst_ip'),
                    'issue': 'DNS query timeout - no response received',
                    'query_time': query_data.get('query_time')
                })
            else:
                # Check DNS response time
                response_time = query_data.get('response_time', 0)
                if response_time > 5.0:  # More than 5 seconds
                    self.results['advanced_analysis']['dns_issues'].append({
                        'type': 'dns_slow_response',
                        'query_id': query_id,
                        'domain': query_data.get('domain'),
                        'response_time': response_time,
                        'issue': f'Slow DNS response: {response_time:.2f}s'
                    })
    
    def _analyze_https_issues(self):
        """Analyze HTTPS/SSL connection issues."""
        https_connections = []
        
        # Find HTTPS connections (port 443)
        for conn_id, conn_data in self.connections.items():
            if conn_data.get('dst_port') == 443 or conn_data.get('src_port') == 443:
                https_connections.append(conn_data)
        
        for conn in https_connections:
            # Check for connection failures to port 443
            if not conn.get('established', False):
                self.results['advanced_analysis']['https_errors'].append({
                    'type': 'https_connection_failed',
                    'src_ip': conn.get('src_ip'),
                    'dst_ip': conn.get('dst_ip'),
                    'issue': 'HTTPS connection failed to establish',
                    'packets': len(conn.get('packets', [])),
                    'duration': conn.get('duration', 0)
                })
            
            # Check for RST on HTTPS connections
            rst_packets = [p for p in conn.get('packets', []) if p.get('flags', {}).get('RST', False)]
            if rst_packets:
                self.results['advanced_analysis']['https_errors'].append({
                    'type': 'https_connection_reset',
                    'src_ip': conn.get('src_ip'),
                    'dst_ip': conn.get('dst_ip'),
                    'issue': f'HTTPS connection reset ({len(rst_packets)} RST packets)',
                    'rst_count': len(rst_packets)
                })
    
    def _analyze_latency_issues(self):
        """Analyze network latency patterns."""
        if len(self.timing_data) < 2:
            return
        
        # Calculate inter-packet delays
        delays = []
        for i in range(1, len(self.timing_data)):
            delay = self.timing_data[i] - self.timing_data[i-1]
            delays.append(delay)
        
        if delays:
            avg_delay = statistics.mean(delays)
            max_delay = max(delays)
            min_delay = min(delays)
            
            # Detect high latency periods
            high_latency_threshold = avg_delay * 3  # 3x average delay
            high_latency_periods = [d for d in delays if d > high_latency_threshold]
            
            if high_latency_periods:
                # Find packets affected by high latency
                affected_packets = []
                for i, delay in enumerate(delays):
                    if delay > high_latency_threshold:
                        # Find corresponding packets around this time
                        time_window_start = self.timing_data[i]
                        time_window_end = self.timing_data[i + 1]
                        
                        # Look for packets in this time window
                        for protocol in ['dns', 'http', 'https', 'tcp', 'udp']:
                            for packet in self.results[protocol]:
                                if 'time' in packet:
                                    if time_window_start <= packet['time'] <= time_window_end:
                                        affected_packets.append({
                                            'timestamp': packet['timestamp'],
                                            'src_ip': packet.get('src_ip'),
                                            'dst_ip': packet.get('dst_ip'),
                                            'protocol': protocol.upper(),
                                            'delay': delay,
                                            'size': packet.get('size', 0)
                                        })
                
                self.results['advanced_analysis']['latency_issues'].append({
                    'type': 'high_latency_detected',
                    'avg_delay': avg_delay,
                    'max_delay': max_delay,
                    'min_delay': min_delay,
                    'high_latency_periods': len(high_latency_periods),
                    'affected_packets': affected_packets[:10],  # Limit to first 10 for display
                    'total_affected_packets': len(affected_packets),
                    'issue': f'Detected {len(high_latency_periods)} high latency periods (>{high_latency_threshold:.3f}s) affecting {len(affected_packets)} packets'
                })
    
    def _detect_retry_patterns(self):
        """Detect retry patterns in network traffic."""
        # Group packets by source-destination pairs
        connection_attempts = defaultdict(list)
        
        for conn_id, conn_data in self.connections.items():
            key = f"{conn_data.get('src_ip')}-{conn_data.get('dst_ip')}-{conn_data.get('dst_port')}"
            connection_attempts[key].append(conn_data)
        
        # Analyze retry patterns
        for key, attempts in connection_attempts.items():
            if len(attempts) > 1:
                # Multiple connection attempts to same destination
                failed_attempts = [a for a in attempts if not a.get('established', False)]
                if failed_attempts:
                    self.results['advanced_analysis']['retry_patterns'].append({
                        'type': 'connection_retries',
                        'connection_key': key,
                        'total_attempts': len(attempts),
                        'failed_attempts': len(failed_attempts),
                        'issue': f'Multiple connection attempts ({len(attempts)}) with {len(failed_attempts)} failures'
                    })
    
    def _analyze_connection_blocks(self):
        """Analyze potential connection blocks."""
        import ipaddress
        
        # Look for patterns that might indicate blocking
        blocked_ips = {}
        
        for conn_id, conn_data in self.connections.items():
            if not conn_data.get('established', False):
                # Check if multiple connections to same IP failed
                dst_ip = conn_data.get('dst_ip')
                if dst_ip:
                    # Skip private IPs - they're internal network addresses
                    try:
                        ip = ipaddress.ip_address(dst_ip)
                        if ip.is_private:
                            continue  # Skip private IPs
                    except ValueError:
                        # Skip invalid IP addresses
                        continue
                    
                    failed_connections_to_ip = sum(1 for c in self.connections.values() 
                                                if c.get('dst_ip') == dst_ip and not c.get('established', False))
                    if failed_connections_to_ip > 2:  # More than 2 failed connections to same IP
                        if dst_ip not in blocked_ips:
                            blocked_ips[dst_ip] = {
                                'failed_connections': failed_connections_to_ip,
                                'http_errors': [],
                                'ports': set()
                            }
                        blocked_ips[dst_ip]['ports'].add(conn_data.get('dst_port', 'Unknown'))
        
        # Check for HTTP errors to the same IPs
        for http_packet in self.results['http'] + self.results['https']:
            if 'status_code' in http_packet:
                dst_ip = http_packet.get('dst_ip')
                if dst_ip in blocked_ips:
                    status_code = int(http_packet['status_code'])
                    if status_code >= 400:  # Any HTTP error
                        blocked_ips[dst_ip]['http_errors'].append({
                            'status_code': status_code,
                            'timestamp': http_packet['timestamp'],
                            'reason': http_packet.get('reason_phrase', ''),
                            'description': self._get_http_error_description(status_code)
                        })
        
        for blocked_ip, block_data in blocked_ips.items():
            # Determine likely cause of blocking
            likely_causes = []
            if block_data['http_errors']:
                error_codes = [e['status_code'] for e in block_data['http_errors']]
                if 403 in error_codes:
                    likely_causes.append("403 Forbidden - Access denied by server")
                if 404 in error_codes:
                    likely_causes.append("404 Not Found - Resource doesn't exist")
                if 429 in error_codes:
                    likely_causes.append("429 Too Many Requests - Rate limiting")
                if any(code >= 500 for code in error_codes):
                    likely_causes.append("5xx Server Errors - Server issues")
            
            if not likely_causes:
                likely_causes.append("Multiple connection failures - Possible firewall/network blocking")
            
            self.results['advanced_analysis']['blocked_connections'].append({
                'type': 'potential_block',
                'blocked_ip': blocked_ip,
                'failed_connections': block_data['failed_connections'],
                'affected_ports': list(block_data['ports']),
                'http_errors': block_data['http_errors'],
                'likely_causes': likely_causes,
                'issue': f'Multiple failed connections to {blocked_ip} - possible blocking'
            })
    
    def _analyze_http_errors(self):
        """Analyze HTTP errors and server issues."""
        # Analyze HTTP responses for error codes
        for http_packet in self.results['http']:
            if 'status_code' in http_packet:
                status_code = int(http_packet['status_code'])
                
                # Server errors (5xx)
                if 500 <= status_code < 600:
                    self.results['advanced_analysis']['server_errors'].append({
                        'type': 'server_error',
                        'status_code': status_code,
                        'src_ip': http_packet['src_ip'],
                        'dst_ip': http_packet['dst_ip'],
                        'timestamp': http_packet['timestamp'],
                        'issue': f'Server error {status_code}: {self._get_http_error_description(status_code)}',
                        'reason_phrase': http_packet.get('reason_phrase', '')
                    })
                
                # Client errors (4xx)
                elif 400 <= status_code < 500:
                    self.results['advanced_analysis']['client_errors'].append({
                        'type': 'client_error',
                        'status_code': status_code,
                        'src_ip': http_packet['src_ip'],
                        'dst_ip': http_packet['dst_ip'],
                        'timestamp': http_packet['timestamp'],
                        'issue': f'Client error {status_code}: {self._get_http_error_description(status_code)}',
                        'reason_phrase': http_packet.get('reason_phrase', '')
                    })
                
                # Redirect issues (3xx)
                elif 300 <= status_code < 400:
                    self.results['advanced_analysis']['redirect_issues'].append({
                        'type': 'redirect',
                        'status_code': status_code,
                        'src_ip': http_packet['src_ip'],
                        'dst_ip': http_packet['dst_ip'],
                        'timestamp': http_packet['timestamp'],
                        'issue': f'HTTP redirect {status_code}: {self._get_http_error_description(status_code)}',
                        'reason_phrase': http_packet.get('reason_phrase', '')
                    })
        
        # Analyze HTTPS responses for error codes
        for https_packet in self.results['https']:
            if 'status_code' in https_packet:
                status_code = int(https_packet['status_code'])
                
                # Server errors (5xx)
                if 500 <= status_code < 600:
                    self.results['advanced_analysis']['server_errors'].append({
                        'type': 'https_server_error',
                        'status_code': status_code,
                        'src_ip': https_packet['src_ip'],
                        'dst_ip': https_packet['dst_ip'],
                        'timestamp': https_packet['timestamp'],
                        'issue': f'HTTPS server error {status_code}: {self._get_http_error_description(status_code)}',
                        'reason_phrase': https_packet.get('reason_phrase', '')
                    })
                
                # Client errors (4xx)
                elif 400 <= status_code < 500:
                    self.results['advanced_analysis']['client_errors'].append({
                        'type': 'https_client_error',
                        'status_code': status_code,
                        'src_ip': https_packet['src_ip'],
                        'dst_ip': https_packet['dst_ip'],
                        'timestamp': https_packet['timestamp'],
                        'issue': f'HTTPS client error {status_code}: {self._get_http_error_description(status_code)}',
                        'reason_phrase': https_packet.get('reason_phrase', '')
                    })
        
        # Detect redirect chains and potential loops
        self._detect_redirect_chains()
        
        # Detect HTTP timeouts and connection issues
        self._detect_http_timeouts()
    
    def _get_http_error_description(self, status_code: int) -> str:
        """Get human-readable description for HTTP status codes."""
        descriptions = {
            # 4xx Client Errors
            400: "Bad Request - Invalid request syntax",
            401: "Unauthorized - Authentication required",
            403: "Forbidden - Server refuses to authorize",
            404: "Not Found - Resource not found",
            405: "Method Not Allowed - HTTP method not supported",
            408: "Request Timeout - Server timeout waiting for request",
            409: "Conflict - Request conflicts with current state",
            410: "Gone - Resource no longer available",
            413: "Payload Too Large - Request entity too large",
            414: "URI Too Long - Request URI too long",
            415: "Unsupported Media Type - Media format not supported",
            429: "Too Many Requests - Rate limit exceeded",
            
            # 5xx Server Errors
            500: "Internal Server Error - Server encountered unexpected condition",
            501: "Not Implemented - Server doesn't support request method",
            502: "Bad Gateway - Invalid response from upstream server",
            503: "Service Unavailable - Server temporarily overloaded",
            504: "Gateway Timeout - Upstream server timeout",
            505: "HTTP Version Not Supported - HTTP version not supported",
            
            # 3xx Redirects
            301: "Moved Permanently - Resource permanently moved",
            302: "Found - Resource temporarily moved",
            303: "See Other - Resource at different location",
            304: "Not Modified - Resource not modified",
            307: "Temporary Redirect - Resource temporarily moved",
            308: "Permanent Redirect - Resource permanently moved"
        }
        return descriptions.get(status_code, f"Unknown status code {status_code}")
    
    def _detect_redirect_chains(self):
        """Detect redirect chains and potential redirect loops."""
        # Group HTTP responses by source IP to detect redirect patterns
        redirects_by_ip = defaultdict(list)
        
        for http_packet in self.results['http'] + self.results['https']:
            if 'status_code' in http_packet:
                status_code = int(http_packet['status_code'])
                if 300 <= status_code < 400:  # Redirect status codes
                    redirects_by_ip[http_packet['src_ip']].append({
                        'status_code': status_code,
                        'timestamp': http_packet['timestamp'],
                        'dst_ip': http_packet['dst_ip']
                    })
        
        # Analyze redirect patterns
        for src_ip, redirects in redirects_by_ip.items():
            if len(redirects) > 3:  # Multiple redirects from same source
                self.results['advanced_analysis']['redirect_issues'].append({
                    'type': 'redirect_chain',
                    'src_ip': src_ip,
                    'redirect_count': len(redirects),
                    'issue': f'Multiple redirects detected ({len(redirects)}) - possible redirect chain or loop',
                    'redirects': redirects
                })
    
    def _detect_http_timeouts(self):
        """Detect HTTP timeouts and connection issues."""
        # Look for HTTP requests without corresponding responses
        http_requests = [p for p in self.results['http'] if 'method' in p]
        http_responses = [p for p in self.results['http'] if 'status_code' in p]
        
        # Simple timeout detection based on request-response pairs
        for request in http_requests:
            # Check if there's a corresponding response within reasonable time
            request_time = request.get('time', 0)
            corresponding_responses = [
                resp for resp in http_responses 
                if resp.get('dst_ip') == request.get('src_ip') and 
                   resp.get('src_ip') == request.get('dst_ip') and
                   abs(resp.get('time', 0) - request_time) < 30  # 30 second window
            ]
            
            if not corresponding_responses:
                self.results['advanced_analysis']['http_errors'].append({
                    'type': 'http_timeout',
                    'src_ip': request['src_ip'],
                    'dst_ip': request['dst_ip'],
                    'method': request.get('method'),
                    'path': request.get('path'),
                    'timestamp': request['timestamp'],
                    'issue': f'HTTP request timeout - no response received for {request.get("method")} {request.get("path")}'
                })
    
    def _classify_ip_addresses(self):
        """Classify IP addresses as private or public."""
        import ipaddress
        
        private_ips = []
        public_ips = []
        
        for ip_str in self.ip_addresses:
            try:
                ip = ipaddress.ip_address(ip_str)
                if ip.is_private:
                    private_ips.append(ip_str)
                else:
                    public_ips.append(ip_str)
            except ValueError:
                # Skip invalid IP addresses
                continue
        
        # Store classification in results
        self.results['ip_classification'] = {
            'private_ips': sorted(private_ips),
            'public_ips': sorted(public_ips),
            'total_private': len(private_ips),
            'total_public': len(public_ips),
            'total_unique_ips': len(self.ip_addresses)
        }
    
    def _analyze_protocol_deep_dive(self):
        """Analyze specific protocols in detail."""
        # Analyze TLS/SSL issues
        self._analyze_tls_issues()
        
        # Analyze SMTP issues
        self._analyze_smtp_issues()
        
        # Analyze FTP issues
        self._analyze_ftp_issues()
        
        # Analyze SMB issues
        self._analyze_smb_issues()
    
    def _analyze_tls_issues(self):
        """Analyze TLS/SSL connection issues."""
        # Look for TLS handshake failures
        tls_connections = []
        for conn_id, conn_data in self.connections.items():
            if conn_data.get('dst_port') == 443 or conn_data.get('src_port') == 443:
                tls_connections.append(conn_data)
        
        for conn in tls_connections:
            if not conn.get('established', False):
                self.results['advanced_analysis']['tls_issues'].append({
                    'type': 'tls_handshake_failed',
                    'src_ip': conn.get('src_ip'),
                    'dst_ip': conn.get('dst_ip'),
                    'issue': 'TLS handshake failed - possible SSL/TLS configuration issue',
                    'packets': len(conn.get('packets', [])),
                    'duration': conn.get('duration', 0)
                })
    
    def _analyze_smtp_issues(self):
        """Analyze SMTP email protocol issues."""
        smtp_ports = [25, 587, 465]  # Standard SMTP ports
        smtp_connections = []
        
        for conn_id, conn_data in self.connections.items():
            if conn_data.get('dst_port') in smtp_ports or conn_data.get('src_port') in smtp_ports:
                smtp_connections.append(conn_data)
        
        for conn in smtp_connections:
            if not conn.get('established', False):
                self.results['advanced_analysis']['smtp_issues'].append({
                    'type': 'smtp_connection_failed',
                    'src_ip': conn.get('src_ip'),
                    'dst_ip': conn.get('dst_ip'),
                    'port': conn.get('dst_port'),
                    'issue': f'SMTP connection failed on port {conn.get("dst_port")} - email delivery issues',
                    'packets': len(conn.get('packets', [])),
                    'duration': conn.get('duration', 0)
                })
    
    def _analyze_ftp_issues(self):
        """Analyze FTP file transfer issues."""
        ftp_ports = [21, 20, 22]  # FTP control, data, and SFTP
        ftp_connections = []
        
        for conn_id, conn_data in self.connections.items():
            if conn_data.get('dst_port') in ftp_ports or conn_data.get('src_port') in ftp_ports:
                ftp_connections.append(conn_data)
        
        for conn in ftp_connections:
            if not conn.get('established', False):
                port_type = "FTP Control" if conn.get('dst_port') == 21 else "FTP Data" if conn.get('dst_port') == 20 else "SFTP"
                self.results['advanced_analysis']['ftp_issues'].append({
                    'type': 'ftp_connection_failed',
                    'src_ip': conn.get('src_ip'),
                    'dst_ip': conn.get('dst_ip'),
                    'port': conn.get('dst_port'),
                    'issue': f'{port_type} connection failed - file transfer issues',
                    'packets': len(conn.get('packets', [])),
                    'duration': conn.get('duration', 0)
                })
    
    def _analyze_smb_issues(self):
        """Analyze SMB Windows file sharing issues."""
        smb_ports = [445, 139]  # SMB ports
        smb_connections = []
        
        for conn_id, conn_data in self.connections.items():
            if conn_data.get('dst_port') in smb_ports or conn_data.get('src_port') in smb_ports:
                smb_connections.append(conn_data)
        
        for conn in smb_connections:
            if not conn.get('established', False):
                port_type = "SMB" if conn.get('dst_port') == 445 else "NetBIOS"
                self.results['advanced_analysis']['smb_issues'].append({
                    'type': 'smb_connection_failed',
                    'src_ip': conn.get('src_ip'),
                    'dst_ip': conn.get('dst_ip'),
                    'port': conn.get('dst_port'),
                    'issue': f'{port_type} connection failed - Windows file sharing issues',
                    'packets': len(conn.get('packets', [])),
                    'duration': conn.get('duration', 0)
                })
    
    def _analyze_performance_metrics(self):
        """Analyze network performance metrics."""
        # Analyze bandwidth utilization
        self._analyze_bandwidth_utilization()
        
        # Detect packet loss
        self._detect_packet_loss()
        
        # Analyze jitter
        self._analyze_jitter()
        
        # Calculate throughput metrics
        self._calculate_throughput_metrics()
    
    def _analyze_bandwidth_utilization(self):
        """Analyze bandwidth utilization patterns."""
        if len(self.timing_data) < 2:
            return
        
        # Calculate bytes per second over time windows
        time_windows = []
        window_size = 1.0  # 1 second windows
        
        start_time = min(self.timing_data)
        end_time = max(self.timing_data)
        
        current_time = start_time
        while current_time < end_time:
            window_end = current_time + window_size
            window_bytes = 0
            
            # Count bytes in this time window
            for protocol in ['dns', 'http', 'https', 'tcp', 'udp', 'icmp']:
                for packet in self.results[protocol]:
                    if 'time' in packet and 'size' in packet:
                        if current_time <= packet['time'] <= window_end:
                            window_bytes += packet['size']
            
            if window_bytes > 0:
                time_windows.append({
                    'time': current_time,
                    'bytes': window_bytes,
                    'mbps': (window_bytes * 8) / (1024 * 1024)  # Convert to Mbps
                })
            
            current_time += window_size
        
        if time_windows:
            # Find peak utilization
            max_utilization = max(time_windows, key=lambda x: x['mbps'])
            avg_utilization = sum(w['mbps'] for w in time_windows) / len(time_windows)
            
            self.results['advanced_analysis']['bandwidth_analysis'].append({
                'type': 'bandwidth_utilization',
                'peak_mbps': max_utilization['mbps'],
                'avg_mbps': avg_utilization,
                'peak_time': datetime.fromtimestamp(max_utilization['time']).isoformat(),
                'total_windows': len(time_windows),
                'issue': f'Peak bandwidth: {max_utilization["mbps"]:.2f} Mbps at {datetime.fromtimestamp(max_utilization["time"]).strftime("%H:%M:%S")}'
            })
    
    def _detect_packet_loss(self):
        """Detect potential packet loss in TCP connections."""
        for conn_id, conn_data in self.connections.items():
            if conn_data.get('established', False):
                packets = conn_data.get('packets', [])
                if len(packets) > 10:  # Only analyze connections with enough packets
                    # Look for TCP sequence number gaps
                    tcp_packets = [p for p in packets if 'seq' in p]
                    if len(tcp_packets) > 1:
                        # Simple packet loss detection based on timing gaps
                        time_gaps = []
                        for i in range(1, len(tcp_packets)):
                            gap = tcp_packets[i].get('time', 0) - tcp_packets[i-1].get('time', 0)
                            time_gaps.append(gap)
                        
                        if time_gaps:
                            avg_gap = statistics.mean(time_gaps)
                            max_gap = max(time_gaps)
                            
                            # If max gap is significantly larger than average, possible packet loss
                            if max_gap > avg_gap * 5:  # 5x average gap
                                self.results['advanced_analysis']['packet_loss'].append({
                                    'type': 'potential_packet_loss',
                                    'connection_id': conn_id,
                                    'src_ip': conn_data.get('src_ip'),
                                    'dst_ip': conn_data.get('dst_ip'),
                                    'max_gap': max_gap,
                                    'avg_gap': avg_gap,
                                    'issue': f'Potential packet loss detected - max gap {max_gap:.3f}s vs avg {avg_gap:.3f}s'
                                })
    
    def _analyze_jitter(self):
        """Analyze network jitter (packet timing variation)."""
        if len(self.timing_data) < 3:
            return
        
        # Calculate inter-packet delays
        delays = []
        for i in range(1, len(self.timing_data)):
            delay = self.timing_data[i] - self.timing_data[i-1]
            delays.append(delay)
        
        if delays:
            avg_delay = statistics.mean(delays)
            delay_variance = statistics.variance(delays) if len(delays) > 1 else 0
            jitter = delay_variance ** 0.5  # Standard deviation as jitter measure
            
            # High jitter indicates network instability
            if jitter > avg_delay * 0.5:  # Jitter > 50% of average delay
                self.results['advanced_analysis']['jitter_analysis'].append({
                    'type': 'high_jitter_detected',
                    'avg_delay': avg_delay,
                    'jitter': jitter,
                    'jitter_percentage': (jitter / avg_delay) * 100,
                    'issue': f'High network jitter detected: {jitter:.3f}s ({(jitter/avg_delay)*100:.1f}% of avg delay)'
                })
    
    def _calculate_throughput_metrics(self):
        """Calculate overall throughput metrics."""
        total_bytes = 0
        total_duration = 0
        
        if self.timing_data:
            total_duration = max(self.timing_data) - min(self.timing_data)
        
        # Sum all packet sizes
        for protocol in ['dns', 'http', 'https', 'tcp', 'udp', 'icmp']:
            for packet in self.results[protocol]:
                if 'size' in packet:
                    total_bytes += packet['size']
        
        if total_duration > 0:
            avg_throughput = (total_bytes * 8) / (total_duration * 1024 * 1024)  # Mbps
            
            self.results['advanced_analysis']['performance_metrics'].append({
                'type': 'throughput_summary',
                'total_bytes': total_bytes,
                'total_duration': total_duration,
                'avg_throughput_mbps': avg_throughput,
                'total_packets': self.stats['total_packets'],
                'packets_per_second': self.stats['total_packets'] / total_duration if total_duration > 0 else 0,
                'issue': f'Average throughput: {avg_throughput:.2f} Mbps over {total_duration:.1f}s'
            })
    
    def _analyze_security_issues(self):
        """Analyze security-related issues and suspicious patterns."""
        # Detect port scanning
        self._detect_port_scanning()
        
        # Detect rapid connections
        self._detect_rapid_connections()
        
        # Detect suspicious patterns
        self._detect_suspicious_patterns()
        
        # Detect anomalies
        self._detect_anomalies()
        
        # Check for known bad IPs
        self._check_known_bad_ips()
    
    def _detect_port_scanning(self):
        """Detect potential port scanning activity."""
        # Group connections by source IP
        connections_by_src = defaultdict(list)
        
        for conn_id, conn_data in self.connections.items():
            src_ip = conn_data.get('src_ip')
            if src_ip:
                connections_by_src[src_ip].append(conn_data)
        
        # Check for port scanning patterns
        for src_ip, connections in connections_by_src.items():
            if len(connections) > 10:  # More than 10 connection attempts
                # Check if connections are to different ports
                unique_ports = set()
                unique_dst_ips = set()
                
                for conn in connections:
                    unique_ports.add(conn.get('dst_port'))
                    unique_dst_ips.add(conn.get('dst_ip'))
                
                # Port scanning: many different ports, few destinations
                if len(unique_ports) > 5 and len(unique_dst_ips) < 3:
                    self.results['advanced_analysis']['port_scanning'].append({
                        'type': 'port_scan_detected',
                        'src_ip': src_ip,
                        'unique_ports': len(unique_ports),
                        'unique_destinations': len(unique_dst_ips),
                        'total_attempts': len(connections),
                        'ports_scanned': sorted(list(unique_ports)),
                        'issue': f'Potential port scan from {src_ip} - {len(unique_ports)} ports on {len(unique_dst_ips)} hosts'
                    })
                
                # Host scanning: many different destinations, few ports
                elif len(unique_dst_ips) > 5 and len(unique_ports) < 3:
                    self.results['advanced_analysis']['port_scanning'].append({
                        'type': 'host_scan_detected',
                        'src_ip': src_ip,
                        'unique_ports': len(unique_ports),
                        'unique_destinations': len(unique_dst_ips),
                        'total_attempts': len(connections),
                        'targets_scanned': sorted(list(unique_dst_ips)),
                        'ports_scanned': sorted(list(unique_ports)),
                        'issue': f'Potential host scan from {src_ip} - {len(unique_dst_ips)} hosts on {len(unique_ports)} ports'
                    })
    
    def _detect_rapid_connections(self):
        """Detect rapid connection attempts (potential DoS or brute force)."""
        # Group connections by source IP and time
        connections_by_src = defaultdict(list)
        
        for conn_id, conn_data in self.connections.items():
            src_ip = conn_data.get('src_ip')
            if src_ip and 'start_time' in conn_data:
                connections_by_src[src_ip].append(conn_data)
        
        for src_ip, connections in connections_by_src.items():
            if len(connections) > 5:  # More than 5 connection attempts
                # Sort by start time
                connections.sort(key=lambda x: x.get('start_time', 0))
                
                # Check for rapid succession
                rapid_connections = []
                for i in range(1, len(connections)):
                    time_diff = connections[i].get('start_time', 0) - connections[i-1].get('start_time', 0)
                    if time_diff < 1.0:  # Less than 1 second between connections
                        rapid_connections.append(connections[i])
                
                if len(rapid_connections) > 3:  # More than 3 rapid connections
                    self.results['advanced_analysis']['rapid_connections'].append({
                        'type': 'rapid_connection_attempts',
                        'src_ip': src_ip,
                        'rapid_connections': len(rapid_connections),
                        'total_connections': len(connections),
                        'time_window': '1 second',
                        'issue': f'Rapid connection attempts from {src_ip} - {len(rapid_connections)} connections in <1s'
                    })
    
    def _detect_suspicious_patterns(self):
        """Detect suspicious network patterns."""
        # Check for unusual port usage
        port_usage = defaultdict(int)
        for conn_id, conn_data in self.connections.items():
            port = conn_data.get('dst_port')
            if port:
                port_usage[port] += 1
        
        # Flag unusual ports
        suspicious_ports = []
        for port, count in port_usage.items():
            if port in [22, 23, 135, 139, 445, 1433, 3389, 5432, 3306]:  # Common admin/database ports
                if count > 5:  # Multiple attempts to admin ports
                    suspicious_ports.append({
                        'port': port,
                        'attempts': count,
                        'port_name': self._get_port_name(port)
                    })
        
        if suspicious_ports:
            port_list = ", ".join([f"{p['port']} ({p['port_name']})" for p in suspicious_ports])
            self.results['advanced_analysis']['suspicious_patterns'].append({
                'type': 'suspicious_port_usage',
                'suspicious_ports': suspicious_ports,
                'issue': f'Multiple attempts to administrative ports: {port_list}'
            })
        
        # Check for failed authentication attempts
        failed_auth_attempts = 0
        for conn_id, conn_data in self.connections.items():
            if not conn_data.get('established', False):
                port = conn_data.get('dst_port')
                if port in [22, 23, 21, 25, 110, 143, 993, 995]:  # Common auth ports
                    failed_auth_attempts += 1
        
        if failed_auth_attempts > 3:
            self.results['advanced_analysis']['suspicious_patterns'].append({
                'type': 'failed_auth_attempts',
                'failed_attempts': failed_auth_attempts,
                'issue': f'Multiple failed authentication attempts ({failed_auth_attempts}) - possible brute force attack'
            })
    
    def _detect_anomalies(self):
        """Detect network anomalies."""
        # Check for unusual traffic patterns
        if self.timing_data:
            total_duration = max(self.timing_data) - min(self.timing_data)
            packets_per_second = len(self.timing_data) / total_duration if total_duration > 0 else 0
            
            # High packet rate might indicate flooding
            if packets_per_second > 1000:  # More than 1000 packets per second
                self.results['advanced_analysis']['anomaly_detection'].append({
                    'type': 'high_packet_rate',
                    'packets_per_second': packets_per_second,
                    'total_packets': len(self.timing_data),
                    'duration': total_duration,
                    'issue': f'Unusually high packet rate: {packets_per_second:.1f} packets/second - possible flooding'
                })
        
        # Check for unusual connection patterns
        connection_rates = defaultdict(int)
        for conn_id, conn_data in self.connections.items():
            src_ip = conn_data.get('src_ip')
            if src_ip:
                connection_rates[src_ip] += 1
        
        # Find IPs with unusually high connection rates
        for src_ip, count in connection_rates.items():
            if count > 20:  # More than 20 connections from same IP
                self.results['advanced_analysis']['anomaly_detection'].append({
                    'type': 'high_connection_rate',
                    'src_ip': src_ip,
                    'connection_count': count,
                    'issue': f'Unusually high connection rate from {src_ip}: {count} connections'
                })
    
    def _check_known_bad_ips(self):
        """Check for connections to known bad IPs and suspicious patterns."""
        import ipaddress
        
        # Check for connections to suspicious IPs
        suspicious_connections = []
        
        for conn_id, conn_data in self.connections.items():
            dst_ip = conn_data.get('dst_ip')
            src_ip = conn_data.get('src_ip')
            port = conn_data.get('dst_port')
            established = conn_data.get('established', False)
            
            if dst_ip:
                reasons = []
                
                # Check for private IP connections (potential lateral movement)
                try:
                    ip = ipaddress.ip_address(dst_ip)
                    if ip.is_private and not established:
                        reasons.append("Failed connection to private IP (potential lateral movement)")
                except ValueError:
                    pass
                
                # Check for connections to reserved/private ranges from external IPs
                if src_ip and not src_ip.startswith('192.168.') and not src_ip.startswith('10.') and not src_ip.startswith('172.'):
                    if dst_ip.startswith('192.168.') or dst_ip.startswith('10.') or dst_ip.startswith('172.'):
                        reasons.append("External IP connecting to private network")
                
                # Check for connections to suspicious ports
                if port in [22, 23, 135, 139, 445, 1433, 3389, 5432, 3306]:
                    if not established:
                        reasons.append(f"Failed connection to administrative port {port} ({self._get_port_name(port)})")
                    else:
                        reasons.append(f"Connection to administrative port {port} ({self._get_port_name(port)})")
                
                # Check for connections to well-known malicious IPs (basic list)
                malicious_ips = [
                    '127.0.0.1',  # Localhost (suspicious if from external)
                    '0.0.0.0',   # Invalid destination
                    '255.255.255.255'  # Broadcast address
                ]
                if dst_ip in malicious_ips:
                    reasons.append(f"Connection to suspicious IP {dst_ip}")
                
                # Check for connections to high-numbered ports (potential backdoors)
                if port and port > 49152:  # Dynamic/private port range
                    if not established:
                        reasons.append(f"Failed connection to high-numbered port {port} (potential backdoor)")
                
                # Check for connections to non-standard ports for common services
                non_standard_ports = {
                    80: [8080, 8000, 8888],  # HTTP alternatives
                    443: [8443, 9443],       # HTTPS alternatives
                    22: [2222, 2200],        # SSH alternatives
                    21: [2121, 2100],        # FTP alternatives
                }
                for standard_port, alternatives in non_standard_ports.items():
                    if port in alternatives:
                        reasons.append(f"Connection to non-standard {self._get_port_name(standard_port)} port {port}")
                
                # Check for multiple failed connections to same IP
                if not established:
                    failed_connections_to_same_ip = sum(1 for c in self.connections.values() 
                                                      if c.get('dst_ip') == dst_ip and not c.get('established', False))
                    if failed_connections_to_same_ip > 3:
                        reasons.append(f"Multiple failed connections ({failed_connections_to_same_ip}) to {dst_ip}")
                
                # Add to suspicious connections if any reasons found
                if reasons:
                    suspicious_connections.append({
                        'src_ip': src_ip,
                        'dst_ip': dst_ip,
                        'port': port,
                        'established': established,
                        'reasons': reasons,
                        'reason': '; '.join(reasons)  # For backward compatibility
                    })
        
        if suspicious_connections:
            self.results['advanced_analysis']['security_issues'].append({
                'type': 'suspicious_connections',
                'suspicious_connections': suspicious_connections,
                'issue': f'Found {len(suspicious_connections)} suspicious connection attempts'
            })
    
    def _get_port_name(self, port):
        """Get common port name for display."""
        port_names = {
            22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL'
        }
        return port_names.get(port, f'Port {port}')
    
    def _generate_summary(self):
        """Generate summary statistics."""
        self.results['summary'] = {
            'total_packets': self.stats['total_packets'],
            'dns_packets': self.stats['dns'],
            'http_packets': self.stats['http'],
            'https_packets': self.stats['https'],
            'icmp_packets': self.stats['icmp'],
            'tcp_packets': self.stats['tcp'],
            'udp_packets': self.stats['udp'],
            'other_packets': self.stats['other'],
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def print_summary(self):
        """Print a summary of the analysis."""
        summary = self.results['summary']
        print("\n" + "="*50)
        print("PCAP ANALYSIS SUMMARY")
        print("="*50)
        print(f"Total Packets: {summary['total_packets']}")
        print(f"DNS Packets: {summary['dns_packets']}")
        print(f"HTTP Packets: {summary['http_packets']}")
        print(f"HTTPS Packets: {summary['https_packets']}")
        print(f"ICMP Packets: {summary['icmp_packets']}")
        print(f"TCP Packets: {summary['tcp_packets']}")
        print(f"UDP Packets: {summary['udp_packets']}")
        print(f"Other Packets: {summary['other_packets']}")
        print("="*50)
    
    def print_ip_classification(self):
        """Print IP address classification."""
        if 'ip_classification' in self.results:
            ip_info = self.results['ip_classification']
            print("\n" + "="*80)
            print("🌐 IP ADDRESS CLASSIFICATION")
            print("="*80)
            print(f"Total Unique IPs: {ip_info['total_unique_ips']}")
            print(f"Private IPs: {ip_info['total_private']}")
            print(f"Public IPs: {ip_info['total_public']}")
            
            if ip_info['private_ips']:
                print(f"\n🏠 PRIVATE IP ADDRESSES ({len(ip_info['private_ips'])}):")
                print("-" * 50)
                for i, ip in enumerate(ip_info['private_ips'][:10]):
                    print(f"{i+1:2d}. {ip}")
                if len(ip_info['private_ips']) > 10:
                    print(f"    ... and {len(ip_info['private_ips']) - 10} more private IPs")
            
            if ip_info['public_ips']:
                print(f"\n🌍 PUBLIC IP ADDRESSES ({len(ip_info['public_ips'])}):")
                print("-" * 50)
                for i, ip in enumerate(ip_info['public_ips'][:10]):
                    print(f"{i+1:2d}. {ip}")
                if len(ip_info['public_ips']) > 10:
                    print(f"    ... and {len(ip_info['public_ips']) - 10} more public IPs")
            
            print("\n" + "="*80)
    
    def print_detailed_results(self):
        """Print detailed results for each protocol."""
        print("\n" + "="*80)
        print("DETAILED PROTOCOL ANALYSIS")
        print("="*80)
        
        # DNS Results
        if self.results['dns']:
            print(f"\n🔍 DNS TRAFFIC ({len(self.results['dns'])} packets):")
            print("-" * 40)
            for i, dns in enumerate(self.results['dns'][:10]):  # Show first 10
                print(f"{i+1:2d}. {dns['timestamp']} | {dns['src_ip']} → {dns['dst_ip']}")
                if dns['questions']:
                    for q in dns['questions']:
                        print(f"     Query: {q['qname']} (Type: {q['qtype']})")
                if dns['answers']:
                    for a in dns['answers']:
                        print(f"     Answer: {a['name']} → {a['rdata']} (TTL: {a['ttl']})")
                print()
            if len(self.results['dns']) > 10:
                print(f"    ... and {len(self.results['dns']) - 10} more DNS packets")
        
        # HTTP Results
        if self.results['http']:
            print(f"\n🌐 HTTP TRAFFIC ({len(self.results['http'])} packets):")
            print("-" * 40)
            for i, http in enumerate(self.results['http'][:10]):
                print(f"{i+1:2d}. {http['timestamp']} | {http['src_ip']}:{http.get('src_port', 'N/A')} → {http['dst_ip']}:{http.get('dst_port', 'N/A')}")
                if 'method' in http:
                    print(f"     {http['method']} {http.get('path', 'N/A')} | Host: {http.get('host', 'N/A')}")
                elif 'status_code' in http:
                    print(f"     Response: {http['status_code']} {http.get('reason_phrase', '')}")
                print()
            if len(self.results['http']) > 10:
                print(f"    ... and {len(self.results['http']) - 10} more HTTP packets")
        
        # HTTPS Results
        if self.results['https']:
            print(f"\n🔒 HTTPS TRAFFIC ({len(self.results['https'])} packets):")
            print("-" * 40)
            for i, https in enumerate(self.results['https'][:10]):
                print(f"{i+1:2d}. {https['timestamp']} | {https['src_ip']}:{https.get('src_port', 'N/A')} → {https['dst_ip']}:{https.get('dst_port', 'N/A')}")
                print(f"     Encrypted HTTPS traffic")
                print()
            if len(self.results['https']) > 10:
                print(f"    ... and {len(self.results['https']) - 10} more HTTPS packets")
        
        # ICMP Results
        if self.results['icmp']:
            print(f"\n📡 ICMP TRAFFIC ({len(self.results['icmp'])} packets):")
            print("-" * 40)
            for i, icmp in enumerate(self.results['icmp'][:10]):
                print(f"{i+1:2d}. {icmp['timestamp']} | {icmp['src_ip']} → {icmp['dst_ip']}")
                print(f"     Type: {icmp['icmp_type']}, Code: {icmp['icmp_code']}")
                if icmp.get('icmp_id'):
                    print(f"     ID: {icmp['icmp_id']}, Seq: {icmp.get('icmp_seq', 'N/A')}")
                print()
            if len(self.results['icmp']) > 10:
                print(f"    ... and {len(self.results['icmp']) - 10} more ICMP packets")
        
        # TCP Results
        if self.results['tcp']:
            print(f"\n🔗 TCP TRAFFIC ({len(self.results['tcp'])} packets):")
            print("-" * 40)
            for i, tcp in enumerate(self.results['tcp'][:10]):
                print(f"{i+1:2d}. {tcp['timestamp']} | {tcp['src_ip']}:{tcp['src_port']} → {tcp['dst_ip']}:{tcp['dst_port']}")
                flags = [k for k, v in tcp['flags'].items() if v]
                print(f"     Flags: {', '.join(flags) if flags else 'None'} | Window: {tcp['window_size']} | Payload: {tcp['payload_size']} bytes")
                print()
            if len(self.results['tcp']) > 10:
                print(f"    ... and {len(self.results['tcp']) - 10} more TCP packets")
        
        # UDP Results
        if self.results['udp']:
            print(f"\n📦 UDP TRAFFIC ({len(self.results['udp'])} packets):")
            print("-" * 40)
            for i, udp in enumerate(self.results['udp'][:10]):
                print(f"{i+1:2d}. {udp['timestamp']} | {udp['src_ip']}:{udp['src_port']} → {udp['dst_ip']}:{udp['dst_port']}")
                print(f"     Length: {udp['length']} | Payload: {udp['payload_size']} bytes")
                print()
            if len(self.results['udp']) > 10:
                print(f"    ... and {len(self.results['udp']) - 10} more UDP packets")
        
        # Other Results
        if self.results['other']:
            print(f"\n❓ OTHER TRAFFIC ({len(self.results['other'])} packets):")
            print("-" * 40)
            for i, other in enumerate(self.results['other'][:5]):
                print(f"{i+1:2d}. {other['timestamp']} | {other['src_ip']} → {other['dst_ip']} | Protocol: {other.get('protocol', 'Unknown')}")
            if len(self.results['other']) > 5:
                print(f"    ... and {len(self.results['other']) - 5} more packets")
        
        print("\n" + "="*80)
    
    def print_advanced_analysis(self):
        """Print advanced network analysis results."""
        advanced = self.results['advanced_analysis']
        
        print("\n" + "="*80)
        print("🔍 ADVANCED NETWORK ANALYSIS")
        print("="*80)
        
        # Connection Issues
        if advanced['connection_issues']:
            print(f"\n⚠️  CONNECTION ISSUES ({len(advanced['connection_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['connection_issues'][:10]):
                print(f"{i+1:2d}. {issue['type'].upper()}: {issue['src_ip']} → {issue['dst_ip']}:{issue.get('dst_port', 'N/A')}")
                print(f"     Issue: {issue['issue']}")
                if 'packets' in issue:
                    print(f"     Packets: {issue['packets']}, Duration: {issue.get('duration', 0):.3f}s")
                print()
            if len(advanced['connection_issues']) > 10:
                print(f"    ... and {len(advanced['connection_issues']) - 10} more connection issues")
        
        # HTTPS Errors
        if advanced['https_errors']:
            print(f"\n🔒 HTTPS/SSL ERRORS ({len(advanced['https_errors'])}):")
            print("-" * 50)
            for i, error in enumerate(advanced['https_errors'][:10]):
                print(f"{i+1:2d}. {error['type'].upper()}: {error['src_ip']} → {error['dst_ip']}")
                print(f"     Issue: {error['issue']}")
                if 'rst_count' in error:
                    print(f"     RST Packets: {error['rst_count']}")
                print()
            if len(advanced['https_errors']) > 10:
                print(f"    ... and {len(advanced['https_errors']) - 10} more HTTPS errors")
        
        # DNS Issues
        if advanced['dns_issues']:
            print(f"\n🌐 DNS ISSUES ({len(advanced['dns_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['dns_issues'][:10]):
                print(f"{i+1:2d}. {issue['type'].upper()}: {issue.get('domain', 'N/A')}")
                print(f"     Issue: {issue['issue']}")
                if 'response_time' in issue:
                    print(f"     Response Time: {issue['response_time']:.3f}s")
                print()
            if len(advanced['dns_issues']) > 10:
                print(f"    ... and {len(advanced['dns_issues']) - 10} more DNS issues")
        
        # Latency Issues
        if advanced['latency_issues']:
            print(f"\n⏱️  LATENCY ISSUES ({len(advanced['latency_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['latency_issues']):
                print(f"{i+1:2d}. {issue['type'].upper()}")
                print(f"     Issue: {issue['issue']}")
                print(f"     Avg Delay: {issue['avg_delay']:.3f}s, Max: {issue['max_delay']:.3f}s")
                print(f"     High Latency Periods: {issue['high_latency_periods']}")
                
                # Show affected packets
                if 'affected_packets' in issue and issue['affected_packets']:
                    print(f"     Affected Packets ({len(issue['affected_packets'])}):")
                    for j, packet in enumerate(issue['affected_packets'][:5]):
                        print(f"       {j+1}. {packet['timestamp']} | {packet['src_ip']} → {packet['dst_ip']} | {packet['protocol']} | Delay: {packet['delay']:.3f}s")
                    if len(issue['affected_packets']) > 5:
                        print(f"       ... and {len(issue['affected_packets']) - 5} more affected packets")
                print()
        
        # Retry Patterns
        if advanced['retry_patterns']:
            print(f"\n🔄 RETRY PATTERNS ({len(advanced['retry_patterns'])}):")
            print("-" * 50)
            for i, pattern in enumerate(advanced['retry_patterns'][:5]):
                print(f"{i+1:2d}. {pattern['type'].upper()}: {pattern['connection_key']}")
                print(f"     Issue: {pattern['issue']}")
                print(f"     Total Attempts: {pattern['total_attempts']}, Failed: {pattern['failed_attempts']}")
                print()
            if len(advanced['retry_patterns']) > 5:
                print(f"    ... and {len(advanced['retry_patterns']) - 5} more retry patterns")
        
        # Blocked Connections
        if advanced['blocked_connections']:
            print(f"\n🚫 POTENTIAL BLOCKS ({len(advanced['blocked_connections'])}):")
            print("-" * 50)
            for i, block in enumerate(advanced['blocked_connections']):
                print(f"{i+1:2d}. {block['type'].upper()}: {block['blocked_ip']}")
                print(f"     Issue: {block['issue']}")
                print(f"     Failed Connections: {block.get('failed_connections', 0)}")
                print(f"     Affected Ports: {', '.join(map(str, block.get('affected_ports', [])))}")
                
                # Show likely causes
                if 'likely_causes' in block and block['likely_causes']:
                    print(f"     Likely Causes:")
                    for cause in block['likely_causes']:
                        print(f"       • {cause}")
                
                # Show HTTP errors if any
                if 'http_errors' in block and block['http_errors']:
                    print(f"     HTTP Errors ({len(block['http_errors'])}):")
                    for error in block['http_errors'][:3]:
                        print(f"       • {error['status_code']} {error['reason']} - {error['description']}")
                    if len(block['http_errors']) > 3:
                        print(f"       ... and {len(block['http_errors']) - 3} more HTTP errors")
                print()
        
        # HTTP Server Errors (5xx)
        if advanced['server_errors']:
            print(f"\n🔥 SERVER ERRORS (5xx) ({len(advanced['server_errors'])}):")
            print("-" * 50)
            for i, error in enumerate(advanced['server_errors'][:10]):
                print(f"{i+1:2d}. {error['type'].upper()}: {error['src_ip']} → {error['dst_ip']}")
                print(f"     Status: {error['status_code']} | {error['issue']}")
                if error.get('reason_phrase'):
                    print(f"     Reason: {error['reason_phrase']}")
                print(f"     Time: {error['timestamp']}")
                print()
            if len(advanced['server_errors']) > 10:
                print(f"    ... and {len(advanced['server_errors']) - 10} more server errors")
        
        # HTTP Client Errors (4xx)
        if advanced['client_errors']:
            print(f"\n⚠️  CLIENT ERRORS (4xx) ({len(advanced['client_errors'])}):")
            print("-" * 50)
            for i, error in enumerate(advanced['client_errors'][:10]):
                print(f"{i+1:2d}. {error['type'].upper()}: {error['src_ip']} → {error['dst_ip']}")
                print(f"     Status: {error['status_code']} | {error['issue']}")
                if error.get('reason_phrase'):
                    print(f"     Reason: {error['reason_phrase']}")
                print(f"     Time: {error['timestamp']}")
                print()
            if len(advanced['client_errors']) > 10:
                print(f"    ... and {len(advanced['client_errors']) - 10} more client errors")
        
        # HTTP Redirects and Issues
        if advanced['redirect_issues']:
            print(f"\n🔄 REDIRECT ISSUES ({len(advanced['redirect_issues'])}):")
            print("-" * 50)
            for i, redirect in enumerate(advanced['redirect_issues'][:5]):
                print(f"{i+1:2d}. {redirect['type'].upper()}: {redirect.get('src_ip', 'N/A')}")
                print(f"     Issue: {redirect['issue']}")
                if 'redirect_count' in redirect:
                    print(f"     Redirect Count: {redirect['redirect_count']}")
                print()
            if len(advanced['redirect_issues']) > 5:
                print(f"    ... and {len(advanced['redirect_issues']) - 5} more redirect issues")
        
        # HTTP Timeouts and General Errors
        if advanced['http_errors']:
            print(f"\n⏰ HTTP TIMEOUTS ({len(advanced['http_errors'])}):")
            print("-" * 50)
            for i, error in enumerate(advanced['http_errors'][:5]):
                print(f"{i+1:2d}. {error['type'].upper()}: {error['src_ip']} → {error['dst_ip']}")
                print(f"     Issue: {error['issue']}")
                if 'method' in error:
                    print(f"     Method: {error['method']} {error.get('path', '')}")
                print(f"     Time: {error['timestamp']}")
                print()
            if len(advanced['http_errors']) > 5:
                print(f"    ... and {len(advanced['http_errors']) - 5} more HTTP errors")
        
        # TLS/SSL Issues
        if advanced['tls_issues']:
            print(f"\n🔒 TLS/SSL ISSUES ({len(advanced['tls_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['tls_issues'][:5]):
                print(f"{i+1:2d}. {issue['type'].upper()}: {issue['src_ip']} → {issue['dst_ip']}")
                print(f"     Issue: {issue['issue']}")
                print(f"     Packets: {issue['packets']}, Duration: {issue['duration']:.3f}s")
                print()
            if len(advanced['tls_issues']) > 5:
                print(f"    ... and {len(advanced['tls_issues']) - 5} more TLS issues")
        
        # SMTP Issues
        if advanced['smtp_issues']:
            print(f"\n📧 SMTP ISSUES ({len(advanced['smtp_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['smtp_issues'][:5]):
                print(f"{i+1:2d}. {issue['type'].upper()}: {issue['src_ip']} → {issue['dst_ip']}:{issue['port']}")
                print(f"     Issue: {issue['issue']}")
                print()
            if len(advanced['smtp_issues']) > 5:
                print(f"    ... and {len(advanced['smtp_issues']) - 5} more SMTP issues")
        
        # FTP Issues
        if advanced['ftp_issues']:
            print(f"\n📁 FTP ISSUES ({len(advanced['ftp_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['ftp_issues'][:5]):
                print(f"{i+1:2d}. {issue['type'].upper()}: {issue['src_ip']} → {issue['dst_ip']}:{issue['port']}")
                print(f"     Issue: {issue['issue']}")
                print()
            if len(advanced['ftp_issues']) > 5:
                print(f"    ... and {len(advanced['ftp_issues']) - 5} more FTP issues")
        
        # SMB Issues
        if advanced['smb_issues']:
            print(f"\n💻 SMB ISSUES ({len(advanced['smb_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['smb_issues'][:5]):
                print(f"{i+1:2d}. {issue['type'].upper()}: {issue['src_ip']} → {issue['dst_ip']}:{issue['port']}")
                print(f"     Issue: {issue['issue']}")
                print()
            if len(advanced['smb_issues']) > 5:
                print(f"    ... and {len(advanced['smb_issues']) - 5} more SMB issues")
        
        # Performance Metrics
        if advanced['performance_metrics']:
            print(f"\n📊 PERFORMANCE METRICS ({len(advanced['performance_metrics'])}):")
            print("-" * 50)
            for i, metric in enumerate(advanced['performance_metrics']):
                print(f"{i+1:2d}. {metric['type'].upper()}")
                print(f"     Issue: {metric['issue']}")
                print(f"     Total Bytes: {metric['total_bytes']:,}")
                print(f"     Duration: {metric['total_duration']:.1f}s")
                print(f"     Packets/sec: {metric['packets_per_second']:.1f}")
                print()
        
        # Bandwidth Analysis
        if advanced['bandwidth_analysis']:
            print(f"\n📈 BANDWIDTH ANALYSIS ({len(advanced['bandwidth_analysis'])}):")
            print("-" * 50)
            for i, analysis in enumerate(advanced['bandwidth_analysis']):
                print(f"{i+1:2d}. {analysis['type'].upper()}")
                print(f"     Issue: {analysis['issue']}")
                print(f"     Peak: {analysis['peak_mbps']:.2f} Mbps")
                print(f"     Average: {analysis['avg_mbps']:.2f} Mbps")
                print()
        
        # Packet Loss
        if advanced['packet_loss']:
            print(f"\n📦 PACKET LOSS ({len(advanced['packet_loss'])}):")
            print("-" * 50)
            for i, loss in enumerate(advanced['packet_loss'][:5]):
                print(f"{i+1:2d}. {loss['type'].upper()}: {loss['src_ip']} → {loss['dst_ip']}")
                print(f"     Issue: {loss['issue']}")
                print()
            if len(advanced['packet_loss']) > 5:
                print(f"    ... and {len(advanced['packet_loss']) - 5} more packet loss issues")
        
        # Jitter Analysis
        if advanced['jitter_analysis']:
            print(f"\n📊 JITTER ANALYSIS ({len(advanced['jitter_analysis'])}):")
            print("-" * 50)
            for i, jitter in enumerate(advanced['jitter_analysis']):
                print(f"{i+1:2d}. {jitter['type'].upper()}")
                print(f"     Issue: {jitter['issue']}")
                print(f"     Jitter: {jitter['jitter']:.3f}s ({jitter['jitter_percentage']:.1f}%)")
                print()
        
        # Security Issues
        if advanced['security_issues']:
            print(f"\n🛡️  SECURITY ISSUES ({len(advanced['security_issues'])}):")
            print("-" * 50)
            for i, issue in enumerate(advanced['security_issues'][:5]):
                print(f"{i+1:2d}. {issue['type'].upper()}")
                print(f"     Issue: {issue['issue']}")
                if 'suspicious_connections' in issue:
                    for conn in issue['suspicious_connections'][:3]:
                        print(f"       • {conn['src_ip']} → {conn['dst_ip']}:{conn['port']}")
                        if 'reasons' in conn:
                            for reason in conn['reasons']:
                                print(f"         - {reason}")
                        else:
                            print(f"         - {conn.get('reason', 'Unknown reason')}")
                print()
            if len(advanced['security_issues']) > 5:
                print(f"    ... and {len(advanced['security_issues']) - 5} more security issues")
        
        # Port Scanning
        if advanced['port_scanning']:
            print(f"\n🔍 PORT SCANNING ({len(advanced['port_scanning'])}):")
            print("-" * 50)
            for i, scan in enumerate(advanced['port_scanning'][:5]):
                print(f"{i+1:2d}. {scan['type'].upper()}: {scan['src_ip']}")
                print(f"     Issue: {scan['issue']}")
                if 'ports_scanned' in scan:
                    print(f"     Ports: {', '.join(map(str, scan['ports_scanned'][:10]))}")
                if 'targets_scanned' in scan:
                    print(f"     Targets: {', '.join(scan['targets_scanned'][:5])}")
                print()
            if len(advanced['port_scanning']) > 5:
                print(f"    ... and {len(advanced['port_scanning']) - 5} more port scans")
        
        # Rapid Connections
        if advanced['rapid_connections']:
            print(f"\n⚡ RAPID CONNECTIONS ({len(advanced['rapid_connections'])}):")
            print("-" * 50)
            for i, rapid in enumerate(advanced['rapid_connections'][:5]):
                print(f"{i+1:2d}. {rapid['type'].upper()}: {rapid['src_ip']}")
                print(f"     Issue: {rapid['issue']}")
                print(f"     Rapid: {rapid['rapid_connections']}, Total: {rapid['total_connections']}")
                print()
            if len(advanced['rapid_connections']) > 5:
                print(f"    ... and {len(advanced['rapid_connections']) - 5} more rapid connection patterns")
        
        # Suspicious Patterns
        if advanced['suspicious_patterns']:
            print(f"\n⚠️  SUSPICIOUS PATTERNS ({len(advanced['suspicious_patterns'])}):")
            print("-" * 50)
            for i, pattern in enumerate(advanced['suspicious_patterns'][:5]):
                print(f"{i+1:2d}. {pattern['type'].upper()}")
                print(f"     Issue: {pattern['issue']}")
                if 'suspicious_ports' in pattern:
                    for port in pattern['suspicious_ports'][:5]:
                        print(f"       • Port {port['port']} ({port['port_name']}): {port['attempts']} attempts")
                if 'failed_attempts' in pattern:
                    print(f"     Failed Auth Attempts: {pattern['failed_attempts']}")
                print()
            if len(advanced['suspicious_patterns']) > 5:
                print(f"    ... and {len(advanced['suspicious_patterns']) - 5} more suspicious patterns")
        
        # Anomaly Detection
        if advanced['anomaly_detection']:
            print(f"\n🚨 ANOMALIES ({len(advanced['anomaly_detection'])}):")
            print("-" * 50)
            for i, anomaly in enumerate(advanced['anomaly_detection'][:5]):
                print(f"{i+1:2d}. {anomaly['type'].upper()}")
                print(f"     Issue: {anomaly['issue']}")
                if 'packets_per_second' in anomaly:
                    print(f"     Rate: {anomaly['packets_per_second']:.1f} packets/sec")
                if 'connection_count' in anomaly:
                    print(f"     Connections: {anomaly['connection_count']}")
                print()
            if len(advanced['anomaly_detection']) > 5:
                print(f"    ... and {len(advanced['anomaly_detection']) - 5} more anomalies")
        
        # Summary of issues
        total_issues = (len(advanced['connection_issues']) + len(advanced['https_errors']) + 
                       len(advanced['dns_issues']) + len(advanced['latency_issues']) + 
                       len(advanced['retry_patterns']) + len(advanced['blocked_connections']) +
                       len(advanced['server_errors']) + len(advanced['client_errors']) + 
                       len(advanced['redirect_issues']) + len(advanced['http_errors']))
        
        if total_issues == 0:
            print("\n✅ No significant network issues detected!")
        else:
            print(f"\n📊 TOTAL ISSUES DETECTED: {total_issues}")
            print(f"   - Connection Issues: {len(advanced['connection_issues'])}")
            print(f"   - HTTPS Errors: {len(advanced['https_errors'])}")
            print(f"   - DNS Issues: {len(advanced['dns_issues'])}")
            print(f"   - Latency Issues: {len(advanced['latency_issues'])}")
            print(f"   - Retry Patterns: {len(advanced['retry_patterns'])}")
            print(f"   - Potential Blocks: {len(advanced['blocked_connections'])}")
            print(f"   - Server Errors (5xx): {len(advanced['server_errors'])}")
            print(f"   - Client Errors (4xx): {len(advanced['client_errors'])}")
            print(f"   - Redirect Issues: {len(advanced['redirect_issues'])}")
            print(f"   - HTTP Timeouts: {len(advanced['http_errors'])}")
            print(f"   - TLS Issues: {len(advanced['tls_issues'])}")
            print(f"   - SMTP Issues: {len(advanced['smtp_issues'])}")
            print(f"   - FTP Issues: {len(advanced['ftp_issues'])}")
            print(f"   - SMB Issues: {len(advanced['smb_issues'])}")
            print(f"   - Performance Issues: {len(advanced['performance_metrics'])}")
            print(f"   - Bandwidth Issues: {len(advanced['bandwidth_analysis'])}")
            print(f"   - Packet Loss: {len(advanced['packet_loss'])}")
            print(f"   - Jitter Issues: {len(advanced['jitter_analysis'])}")
            print(f"   - Security Issues: {len(advanced['security_issues'])}")
            print(f"   - Port Scanning: {len(advanced['port_scanning'])}")
            print(f"   - Rapid Connections: {len(advanced['rapid_connections'])}")
            print(f"   - Suspicious Patterns: {len(advanced['suspicious_patterns'])}")
            print(f"   - Anomalies: {len(advanced['anomaly_detection'])}")
        
        print("\n" + "="*80)
    
    def save_results(self, output_file: str):
        """Save results to JSON file."""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"Results saved to: {output_file}")


def main():
    """Main function to run the PCAP analyzer."""
    parser = argparse.ArgumentParser(description='Analyze PCAP/PCAPNG files and extract traffic by protocol')
    parser.add_argument('pcap_file', help='Path to the PCAP/PCAPNG file to analyze')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output - shows detailed processing steps and progress')
    
    args = parser.parse_args()
    
    # Check if PCAP/PCAPNG file exists
    if not Path(args.pcap_file).exists():
        print(f"Error: PCAP/PCAPNG file '{args.pcap_file}' not found")
        sys.exit(1)
    
    # Check file extension
    file_ext = Path(args.pcap_file).suffix.lower()
    if file_ext not in ['.pcap', '.pcapng', '.cap']:
        print(f"Warning: File extension '{file_ext}' is not a standard PCAP format")
        print("Supported formats: .pcap, .pcapng, .cap")
        print("Attempting to analyze anyway...")
    
    # Create analyzer and run analysis
    analyzer = PCAPAnalyzer(args.pcap_file, verbose=args.verbose)
    results = analyzer.analyze_pcap()
    
    if results:
        analyzer.print_summary()
        analyzer.print_ip_classification()
        analyzer.print_detailed_results()
        analyzer.print_advanced_analysis()
        
        # Save results if output file specified
        if args.output:
            analyzer.save_results(args.output)


if __name__ == "__main__":
    main()
