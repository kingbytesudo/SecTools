#!/usr/bin/env python3
"""
IP Address Extractor
Extracts IPv4 addresses from various file formats with proper sanitization.
Supports: txt, csv, excel, and other text-based files.
"""

import re
import sys
import argparse
import pandas as pd
from pathlib import Path
from typing import List, Set
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class IPExtractor:
    """Extract and validate IPv4 addresses from files."""
    
    def __init__(self):
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        self.subnet_masks = {
            '255.255.255.0', '255.255.255.128', '255.255.255.192', '255.255.255.224',
            '255.255.255.240', '255.255.255.248', '255.255.255.252', '255.255.255.254',
            '255.255.255.255', '255.255.254.0', '255.255.252.0', '255.255.248.0',
            '255.255.240.0', '255.255.224.0', '255.255.192.0', '255.255.128.0',
            '255.255.0.0', '255.254.0.0', '255.252.0.0', '255.248.0.0',
            '255.240.0.0', '255.224.0.0', '255.192.0.0', '255.128.0.0',
            '255.0.0.0', '254.0.0.0', '252.0.0.0', '248.0.0.0',
            '240.0.0.0', '224.0.0.0', '192.0.0.0', '128.0.0.0', '0.0.0.0'
        }
        
    def extract_ips_from_text(self, text: str) -> Set[str]:
        matches = self.ipv4_pattern.findall(text)
        unique_ips = set(matches)
        filtered_ips = unique_ips - self.subnet_masks
        
        logger.info(f"Found {len(unique_ips)} unique IPv4 addresses in text")
        logger.info(f"Filtered out {len(unique_ips - filtered_ips)} subnet masks")
        logger.info(f"Final count: {len(filtered_ips)} valid IP addresses")
        
        return filtered_ips
    
    def read_file(self, file_path: str) -> str:
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        extension = file_path.suffix.lower()
        
        try:
            if extension in ['.txt', '.log', '.csv']:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                logger.info(f"Read text file: {file_path}")
                
            elif extension in ['.xlsx', '.xls']:
                df = pd.read_excel(file_path)
                content = ' '.join(df.astype(str).values.flatten())
                logger.info(f"Read Excel file: {file_path}")
                
            elif extension in ['.csv']:
                df = pd.read_csv(file_path)
                content = ' '.join(df.astype(str).values.flatten())
                logger.info(f"Read CSV file: {file_path}")
                
            else:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                logger.info(f"Read as text file: {file_path}")
                
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            raise
        
        return content
    
    def extract_ips_from_file(self, file_path: str) -> List[str]:
        try:
            content = self.read_file(file_path)
            unique_ips = self.extract_ips_from_text(content)
            ip_list = sorted(list(unique_ips))
            
            logger.info(f"Successfully extracted {len(ip_list)} unique IPv4 addresses from {file_path}")
            return ip_list
            
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            raise
    
    def save_ips_to_file(self, ips: List[str], output_file: str):
        try:
            with open(output_file, 'w') as f:
                for ip in ips:
                    f.write(f"{ip}\n")
            logger.info(f"Saved {len(ips)} IP addresses to {output_file}")
        except Exception as e:
            logger.error(f"Error saving IPs to {output_file}: {str(e)}")
            raise
    
    def print_ips(self, ips: List[str]):
        print(f"\nFound {len(ips)} unique IPv4 addresses:")
        print("-" * 40)
        for i, ip in enumerate(ips, 1):
            print(f"{i:3d}. {ip}")
        print("-" * 40)

def main():
    """Main function to run the IP extractor."""
    parser = argparse.ArgumentParser(
        description="Extract IPv4 addresses from files with sanitization",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_extractor.py input.txt
  python ip_extractor.py data.xlsx -o ips.txt
  python ip_extractor.py logfile.log --verbose
        """
    )
    
    parser.add_argument('input_file', help='Input file to extract IPs from')
    parser.add_argument('-o', '--output', help='Output file to save IPs (optional)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        extractor = IPExtractor()
        ips = extractor.extract_ips_from_file(args.input_file)
        
        if not ips:
            print("No IPv4 addresses found in the file.")
            return
        
        extractor.print_ips(ips)
        
        if args.output:
            extractor.save_ips_to_file(ips, args.output)
            print(f"\nIP addresses saved to: {args.output}")
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()