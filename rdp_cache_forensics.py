#!/usr/bin/env python3
"""
RDP Bitmap Cache Forensics - Proof of Concept
Demonstrates recovery and defensive clearing of RDP bitmap cache artifacts

WARNING: For educational and authorized security testing only.
"""

import os
import sys
import struct
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Optional
from PIL import Image
import argparse


class RDPBitmapCache:
    """
    RDP Bitmap Cache analyzer for forensic artifact recovery
    """
    
    # Common RDP cache locations
    CACHE_PATHS = [
        r"%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache",
        r"%USERPROFILE%\AppData\Local\Microsoft\Terminal Server Client\Cache",
    ]
    
    # Bitmap cache file patterns
    CACHE_PATTERNS = ["bcache*.bmc", "Cache*.bin"]
    
    def __init__(self, cache_dir: Optional[str] = None):
        """Initialize with optional custom cache directory"""
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = self.find_cache_directory()
        self.artifacts = []
        
    def find_cache_directory(self) -> Optional[Path]:
        """Locate the RDP bitmap cache directory"""
        for path_template in self.CACHE_PATHS:
            expanded = os.path.expandvars(path_template)
            cache_path = Path(expanded)
            if cache_path.exists():
                return cache_path
        return None
    
    def enumerate_cache_files(self) -> List[Path]:
        """Find all bitmap cache files"""
        if not self.cache_dir:
            return []
        
        cache_files = []
        for pattern in self.CACHE_PATTERNS:
            cache_files.extend(self.cache_dir.glob(pattern))
        
        return sorted(cache_files)
    
    def parse_bmc_header(self, data: bytes) -> dict:
        """Parse BMC file header structure"""
        if len(data) < 8:
            return {}
        
        # Basic header parsing (simplified)
        try:
            signature = data[:4]
            version = struct.unpack('<I', data[4:8])[0]
            
            return {
                'signature': signature.hex(),
                'version': version,
                'size': len(data),
                'hash': hashlib.sha256(data).hexdigest()[:16]
            }
        except Exception as e:
            return {'error': str(e)}
    
    def extract_bitmap_tiles(self, bmc_file: Path, output_dir: Path) -> int:
        """
        Extract bitmap tiles from cache file
        Note: This is a simplified extraction - real BMC parsing is more complex
        """
        extracted = 0
        
        try:
            with open(bmc_file, 'rb') as f:
                data = f.read()
            
            # Look for common image signatures
            bmp_signatures = [
                b'BM',  # BMP header
                b'\x89PNG',  # PNG header
                b'\xff\xd8\xff'  # JPEG header
            ]
            
            for i, sig in enumerate(bmp_signatures):
                offset = 0
                while True:
                    offset = data.find(sig, offset)
                    if offset == -1:
                        break
                    
                    # Try to extract potential image data
                    chunk_size = min(65536, len(data) - offset)
                    chunk = data[offset:offset + chunk_size]
                    
                    # Save potential bitmap fragment
                    output_file = output_dir / f"{bmc_file.stem}_tile_{extracted:04d}.bin"
                    with open(output_file, 'wb') as out:
                        out.write(chunk)
                    
                    extracted += 1
                    offset += len(sig)
                    
                    if extracted > 100:  # Limit extractions per file
                        break
                
        except Exception as e:
            print(f"Error extracting from {bmc_file}: {e}")
        
        return extracted
    
    def analyze_cache(self, extract: bool = False, output_dir: Optional[Path] = None) -> dict:
        """Perform forensic analysis of RDP bitmap cache"""
        
        if not self.cache_dir:
            return {
                'status': 'error',
                'message': 'RDP cache directory not found'
            }
        
        cache_files = self.enumerate_cache_files()
        
        results = {
            'cache_directory': str(self.cache_dir),
            'timestamp': datetime.now().isoformat(),
            'files_found': len(cache_files),
            'total_size_bytes': 0,
            'files': []
        }
        
        for cache_file in cache_files:
            file_info = {
                'filename': cache_file.name,
                'path': str(cache_file),
                'size_bytes': cache_file.stat().st_size,
                'modified': datetime.fromtimestamp(cache_file.stat().st_mtime).isoformat(),
                'accessed': datetime.fromtimestamp(cache_file.stat().st_atime).isoformat(),
            }
            
            # Parse file header
            try:
                with open(cache_file, 'rb') as f:
                    header_data = f.read(1024)
                file_info['header'] = self.parse_bmc_header(header_data)
            except Exception as e:
                file_info['header_error'] = str(e)
            
            # Extract bitmap tiles if requested
            if extract and output_dir:
                extracted = self.extract_bitmap_tiles(cache_file, output_dir)
                file_info['tiles_extracted'] = extracted
            
            results['total_size_bytes'] += file_info['size_bytes']
            results['files'].append(file_info)
        
        return results
    
    def secure_clear_cache(self, overwrite_passes: int = 3) -> dict:
        """
        Securely clear RDP bitmap cache with multiple overwrite passes
        """
        if not self.cache_dir:
            return {'status': 'error', 'message': 'Cache directory not found'}
        
        cache_files = self.enumerate_cache_files()
        results = {
            'files_processed': 0,
            'files_deleted': 0,
            'errors': [],
            'total_bytes_cleared': 0
        }
        
        for cache_file in cache_files:
            try:
                file_size = cache_file.stat().st_size
                
                # Overwrite file content multiple times
                with open(cache_file, 'r+b') as f:
                    for pass_num in range(overwrite_passes):
                        f.seek(0)
                        # Alternate between zeros and random data
                        if pass_num % 2 == 0:
                            f.write(b'\x00' * file_size)
                        else:
                            f.write(os.urandom(file_size))
                        f.flush()
                        os.fsync(f.fileno())
                
                # Delete the file
                cache_file.unlink()
                
                results['files_deleted'] += 1
                results['total_bytes_cleared'] += file_size
                
            except Exception as e:
                results['errors'].append(f"{cache_file.name}: {str(e)}")
            
            results['files_processed'] += 1
        
        return results


def print_results(results: dict):
    """Print analysis results in readable format"""
    print("\n" + "="*70)
    print("RDP BITMAP CACHE FORENSIC ANALYSIS")
    print("="*70)
    
    if results.get('status') == 'error':
        print(f"\n[!] Error: {results['message']}")
        return
    
    print(f"\nCache Directory: {results['cache_directory']}")
    print(f"Analysis Time: {results['timestamp']}")
    print(f"Files Found: {results['files_found']}")
    print(f"Total Size: {results['total_size_bytes']:,} bytes ({results['total_size_bytes']/1024/1024:.2f} MB)")
    
    if results['files']:
        print("\n" + "-"*70)
        print("CACHE FILES DISCOVERED:")
        print("-"*70)
        
        for idx, file_info in enumerate(results['files'], 1):
            print(f"\n[{idx}] {file_info['filename']}")
            print(f"    Size: {file_info['size_bytes']:,} bytes")
            print(f"    Modified: {file_info['modified']}")
            print(f"    Accessed: {file_info['accessed']}")
            
            if 'header' in file_info and file_info['header']:
                print(f"    Header Signature: {file_info['header'].get('signature', 'N/A')}")
                print(f"    Hash: {file_info['header'].get('hash', 'N/A')}")
            
            if 'tiles_extracted' in file_info:
                print(f"    Tiles Extracted: {file_info['tiles_extracted']}")
    
    print("\n" + "="*70)
    print("SECURITY IMPLICATIONS:")
    print("="*70)
    print("""
• These cache files persist after RDP sessions end
• May contain fragments of sensitive information displayed during sessions
• Can be recovered using forensic tools (BMCViewer, custom parsers)
• Accessible by anyone with file system access to the endpoint
• Should be cleared after sensitive RDP sessions
• Consider disabling bitmap caching for high-security environments
    """)


def print_clear_results(results: dict):
    """Print cache clearing results"""
    print("\n" + "="*70)
    print("RDP BITMAP CACHE SECURE CLEARING")
    print("="*70)
    
    if results.get('status') == 'error':
        print(f"\n[!] Error: {results['message']}")
        return
    
    print(f"\nFiles Processed: {results['files_processed']}")
    print(f"Files Deleted: {results['files_deleted']}")
    print(f"Total Bytes Cleared: {results['total_bytes_cleared']:,} bytes")
    
    if results['errors']:
        print("\nErrors encountered:")
        for error in results['errors']:
            print(f"  - {error}")
    else:
        print("\n[✓] All cache files successfully cleared")


def main():
    parser = argparse.ArgumentParser(
        description='RDP Bitmap Cache Forensics - PoC Tool',
        epilog='For authorized security testing and forensic analysis only'
    )
    
    parser.add_argument(
        '-a', '--analyze',
        action='store_true',
        help='Analyze RDP bitmap cache artifacts'
    )
    
    parser.add_argument(
        '-e', '--extract',
        action='store_true',
        help='Extract bitmap tiles (requires -o/--output)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output directory for extracted artifacts'
    )
    
    parser.add_argument(
        '-c', '--clear',
        action='store_true',
        help='Securely clear RDP bitmap cache (WARNING: destructive)'
    )
    
    parser.add_argument(
        '--cache-dir',
        type=str,
        help='Custom RDP cache directory path'
    )
    
    args = parser.parse_args()
    
    if not any([args.analyze, args.clear]):
        parser.print_help()
        sys.exit(1)
    
    # Initialize analyzer
    analyzer = RDPBitmapCache(cache_dir=args.cache_dir)
    
    if args.analyze:
        output_dir = None
        if args.extract:
            if not args.output:
                print("[!] Error: --extract requires --output directory")
                sys.exit(1)
            output_dir = Path(args.output)
            output_dir.mkdir(parents=True, exist_ok=True)
        
        results = analyzer.analyze_cache(extract=args.extract, output_dir=output_dir)
        print_results(results)
        
        if args.extract and output_dir:
            print(f"\n[✓] Extracted artifacts saved to: {output_dir}")
    
    if args.clear:
        confirm = input("\n[!] WARNING: This will permanently delete cache files. Continue? (yes/no): ")
        if confirm.lower() == 'yes':
            results = analyzer.secure_clear_cache()
            print_clear_results(results)
        else:
            print("Operation cancelled")


if __name__ == "__main__":
    main()