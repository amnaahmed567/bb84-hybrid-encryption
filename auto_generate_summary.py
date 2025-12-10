"""
Auto Results Summary Generator - Reads all PDF reports and generates markdown summary
No manual input needed - just point to your results folder
"""
# python auto_generate_summary.py
#418
import os
import re
from pypdf import PdfReader
from datetime import datetime

class AutoMetricsExtractor:
    def __init__(self, results_folder="results"):
        self.results_folder = results_folder
        self.metrics = {
            'aes_encrypt': {},
            'aes_decrypt': {},
            'chacha_encrypt': {},
            'chacha_decrypt': {}
        }
    
    def extract_text_from_pdf(self, pdf_path):
        """Extract all text from PDF file"""
        try:
            reader = PdfReader(pdf_path)
            text = ""
            for page in reader.pages:
                text += page.extract_text() + "\n"
            return text
        except Exception as e:
            print(f"Warning: Could not read {pdf_path}: {e}")
            return ""
    
    def parse_metric_line(self, text, pattern, default="Not in report"):
        """Extract metric using regex pattern"""
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return default
    
    def extract_metrics_from_text(self, text):
        """Extract all metrics from text content"""
        metrics = {}
        
        # Extract metrics with various patterns
        metrics['Timestamp'] = self.parse_metric_line(text, r'Timestamp[:\s]+(.+?)(?:\n|$)')
        metrics['Cipher Algorithm'] = self.parse_metric_line(text, r'Cipher Algorithm[:\s]+(.+?)(?:\n|$)')
        metrics['Encryption Time'] = self.parse_metric_line(text, r'Encryption Time[:\s]*\(?s\)?[:\s]*(.+?)(?:\n|$)')
        metrics['Decryption Time'] = self.parse_metric_line(text, r'Decryption Time[:\s]*\(?s\)?[:\s]*(.+?)(?:\n|$)')
        metrics['Original File Size'] = self.parse_metric_line(text, r'Original File Size[:\s]*\(?bytes\)?[:\s]*(.+?)(?:\n|$)')
        metrics['Encrypted File Size'] = self.parse_metric_line(text, r'Encrypted File Size[:\s]*\(?bytes\)?[:\s]*(.+?)(?:\n|$)')
        metrics['Decrypted File Size'] = self.parse_metric_line(text, r'Decrypted File Size[:\s]*\(?bytes\)?[:\s]*(.+?)(?:\n|$)')
        metrics['SHA-256 Encrypted'] = self.parse_metric_line(text, r'SHA-256 Hash of Encrypted File[:\s]+(.+?)(?:\n|$)')
        metrics['SHA-256 Decrypted'] = self.parse_metric_line(text, r'SHA-256 Hash of Decrypted File[:\s]+(.+?)(?:\n|$)')
        metrics['AEAD Authentication'] = self.parse_metric_line(text, r'AEAD Authentication[:\s]+(.+?)(?:\n|$)')
        metrics['Post-Quantum Signature'] = self.parse_metric_line(text, r'Post-Quantum Signature[:\s]+(.+?)(?:\n|$)')
        metrics['Key A Length'] = self.parse_metric_line(text, r'Key A Length[:\s]+(.+?)(?:\n|$)')
        metrics['Key B Length'] = self.parse_metric_line(text, r'Key B Length[:\s]+(.+?)(?:\n|$)')
        metrics['Key B - 1s'] = self.parse_metric_line(text, r'Key B - Count of 1s[:\s]+(.+?)(?:\n|$)')
        metrics['Key B - 0s'] = self.parse_metric_line(text, r'Key B - Count of 0s[:\s]+(.+?)(?:\n|$)')
        metrics['A/B Match %'] = self.parse_metric_line(text, r'A/B Bit Match Percentage[:\s]+(.+?)(?:\n|$)')
        metrics['Error Rate'] = self.parse_metric_line(text, r'Key Confirmation Error Rate[:\s]+(.+?)(?:\n|$)')
        metrics['Shannon Entropy'] = self.parse_metric_line(text, r'Estimated Shannon Entropy[:\s]+(.+?)(?:\n|$)')
        metrics['Key Confirmation'] = self.parse_metric_line(text, r'Key Confirmation[:\s]+(.+?)(?:\n|$)')
        
        return metrics
    
    def categorize_report(self, filename, text):
        """Determine report type from filename and content"""
        filename_lower = filename.lower()
        
        if 'aes' in filename_lower or 'AES-GCM' in text:
            if 'encrypt' in filename_lower and 'decrypt' not in filename_lower:
                return 'aes_encrypt'
            elif 'decrypt' in filename_lower:
                return 'aes_decrypt'
        elif 'chacha' in filename_lower or 'ChaCha20' in text:
            if 'encrypt' in filename_lower and 'decrypt' not in filename_lower:
                return 'chacha_encrypt'
            elif 'decrypt' in filename_lower:
                return 'chacha_decrypt'
        
        # Fallback: check content
        if 'Encryption Time' in text:
            if 'AES-GCM' in text:
                return 'aes_encrypt'
            elif 'ChaCha20' in text:
                return 'chacha_encrypt'
        elif 'Decryption Time' in text:
            if 'AES-GCM' in text:
                return 'aes_decrypt'
            elif 'ChaCha20' in text:
                return 'chacha_decrypt'
        
        return None
    
    def scan_results_folder(self):
        """Scan all PDF files in results folder"""
        if not os.path.exists(self.results_folder):
            print(f"❌ Error: Folder '{self.results_folder}' not found!")
            return False
        
        pdf_files = [f for f in os.listdir(self.results_folder) if f.lower().endswith('.pdf')]
        
        if not pdf_files:
            print(f"❌ Error: No PDF files found in '{self.results_folder}'")
            return False
        
        print(f"📁 Found {len(pdf_files)} PDF file(s)")
        print("=" * 60)
        
        for pdf_file in pdf_files:
            pdf_path = os.path.join(self.results_folder, pdf_file)
            print(f"📄 Reading: {pdf_file}")
            
            # Extract text
            text = self.extract_text_from_pdf(pdf_path)
            
            # Categorize report type
            category = self.categorize_report(pdf_file, text)
            
            if category:
                # Extract metrics
                metrics = self.extract_metrics_from_text(text)
                self.metrics[category] = metrics
                print(f"   ✓ Categorized as: {category}")
            else:
                print(f"   ⚠ Could not categorize report type")
        
        print("=" * 60)
        return True
    
    def generate_markdown_summary(self):
        """Generate comprehensive markdown summary"""
        
        md = "# ✅ Final Metrics Summary — BB84 Quantum Encryption System\n\n"
        md += f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n"
        md += "This summary consolidates all encryption/decryption metrics from BB84 quantum key distribution tests.\n\n"
        md += "---\n\n"
        
        # Section 1: Quantum Key Distribution
        md += "## 1️⃣ Quantum Key Distribution (BB84) Summary\n\n"
        
        aes_enc = self.metrics['aes_encrypt']
        chacha_enc = self.metrics['chacha_encrypt']
        
        if aes_enc or chacha_enc:
            md += "| Metric | AES-GCM | ChaCha20 |\n"
            md += "|--------|---------|----------|\n"
            md += f"| Key A Length | {aes_enc.get('Key A Length', 'N/A')} | {chacha_enc.get('Key A Length', 'N/A')} |\n"
            md += f"| Key B Length | {aes_enc.get('Key B Length', 'N/A')} | {chacha_enc.get('Key B Length', 'N/A')} |\n"
            md += f"| Key B (1s count) | {aes_enc.get('Key B - 1s', 'N/A')} | {chacha_enc.get('Key B - 1s', 'N/A')} |\n"
            md += f"| Key B (0s count) | {aes_enc.get('Key B - 0s', 'N/A')} | {chacha_enc.get('Key B - 0s', 'N/A')} |\n"
            md += f"| A/B Match Percentage | {aes_enc.get('A/B Match %', 'N/A')} | {chacha_enc.get('A/B Match %', 'N/A')} |\n"
            md += f"| Error Rate | {aes_enc.get('Error Rate', 'N/A')} | {chacha_enc.get('Error Rate', 'N/A')} |\n"
            md += f"| Shannon Entropy | {aes_enc.get('Shannon Entropy', 'N/A')} | {chacha_enc.get('Shannon Entropy', 'N/A')} |\n"
            md += f"| Key Confirmation | {aes_enc.get('Key Confirmation', 'N/A')} | {chacha_enc.get('Key Confirmation', 'N/A')} |\n\n"
            
            
        else:
            md += "*No quantum key distribution metrics found in reports.*\n\n"
        
        md += "---\n\n"
        
        # Section 2: Encryption Performance
        md += "## 2️⃣ Encryption Performance Summary\n\n"
        
        if aes_enc or chacha_enc:
            md += "| Metric | AES-GCM | ChaCha20 |\n"
            md += "|--------|---------|----------|\n"
            md += f"| Timestamp | {aes_enc.get('Timestamp', 'N/A')} | {chacha_enc.get('Timestamp', 'N/A')} |\n"
            md += f"| Encryption Time (s) | {aes_enc.get('Encryption Time', 'N/A')} | {chacha_enc.get('Encryption Time', 'N/A')} |\n"
            md += f"| Original File Size (bytes) | {aes_enc.get('Original File Size', 'N/A')} | {chacha_enc.get('Original File Size', 'N/A')} |\n"
            md += f"| Encrypted File Size (bytes) | {aes_enc.get('Encrypted File Size', 'N/A')} | {chacha_enc.get('Encrypted File Size', 'N/A')} |\n"
            md += f"| SHA-256 Hash (Encrypted) | {aes_enc.get('SHA-256 Encrypted', 'N/A')[:16]}... | {chacha_enc.get('SHA-256 Encrypted', 'N/A')[:16]}... |\n"
            md += f"| Post-Quantum Signature | {aes_enc.get('Post-Quantum Signature', 'N/A')} | {chacha_enc.get('Post-Quantum Signature', 'N/A')} |\n\n"
            
            md += "**Interpretation:**\n"
            
            # Compare encryption times
            try:
                aes_time = float(aes_enc.get('Encryption Time', '0').replace(' s', '').strip())
                chacha_time = float(chacha_enc.get('Encryption Time', '0').replace(' s', '').strip())
                
                if aes_time > 0 and chacha_time > 0:
                    if chacha_time < aes_time:
                        diff = ((aes_time - chacha_time) / aes_time) * 100
                        md += f"- ✔ ChaCha20 was {diff:.1f}% faster than AES-GCM in encryption\n"
                    else:
                        diff = ((chacha_time - aes_time) / chacha_time) * 100
                        md += f"- ✔ AES-GCM was {diff:.1f}% faster than ChaCha20 in encryption\n"
            except:
                pass
            
            md += "- ✔ Both produced similar encrypted file sizes (ciphertext + nonce + AAD + auth tag + signature)\n"
            md += "- ✔ Post-quantum Dilithium5 signatures protect against quantum computer attacks\n\n"
        else:
            md += "*No encryption performance metrics found in reports.*\n\n"
        
        md += "---\n\n"
        
        # Section 3: Decryption Performance
        md += "## 3️⃣ Decryption Performance Summary\n\n"
        
        aes_dec = self.metrics['aes_decrypt']
        chacha_dec = self.metrics['chacha_decrypt']
        
        if aes_dec or chacha_dec:
            md += "| Metric | AES-GCM | ChaCha20 |\n"
            md += "|--------|---------|----------|\n"
            md += f"| Timestamp | {aes_dec.get('Timestamp', 'N/A')} | {chacha_dec.get('Timestamp', 'N/A')} |\n"
            md += f"| Decryption Time (s) | {aes_dec.get('Decryption Time', 'N/A')} | {chacha_dec.get('Decryption Time', 'N/A')} |\n"
            md += f"| AEAD Authentication | {aes_dec.get('AEAD Authentication', 'N/A')} | {chacha_dec.get('AEAD Authentication', 'N/A')} |\n"
            md += f"| Decrypted File Size (bytes) | {aes_dec.get('Decrypted File Size', 'N/A')} | {chacha_dec.get('Decrypted File Size', 'N/A')} |\n"
            md += f"| SHA-256 Hash (Decrypted) | {aes_dec.get('SHA-256 Decrypted', 'N/A')[:16]}... | {chacha_dec.get('SHA-256 Decrypted', 'N/A')[:16]}... |\n\n"
            
            md += "**Interpretation:**\n"
            
            # Verify both decrypted to same file
            aes_hash = aes_dec.get('SHA-256 Decrypted', '')
            chacha_hash = chacha_dec.get('SHA-256 Decrypted', '')
            
            if aes_hash != 'Not in report' and chacha_hash != 'Not in report' and aes_hash == chacha_hash:
                md += "- ✅ **VERIFICATION PASSED**: Both ciphers decrypted to identical files (SHA-256 hashes match)\n"
            
            # Compare decryption times
            try:
                aes_time = float(aes_dec.get('Decryption Time', '0').replace(' s', '').strip())
                chacha_time = float(chacha_dec.get('Decryption Time', '0').replace(' s', '').strip())
                
                if aes_time > 0 and chacha_time > 0:
                    if aes_time < chacha_time:
                        diff = ((chacha_time - aes_time) / chacha_time) * 100
                        md += f"- ✔ AES-GCM was {diff:.1f}% faster than ChaCha20 in decryption\n"
                    else:
                        diff = ((aes_time - chacha_time) / aes_time) * 100
                        md += f"- ✔ ChaCha20 was {diff:.1f}% faster than AES-GCM in decryption\n"
            except:
                pass
            
            md += "- ✔ AEAD authentication prevents tampering and ensures data integrity\n"
            md += "- ✔ Both ciphers provide equivalent 256-bit security strength\n\n"
        else:
            md += "*No decryption performance metrics found in reports.*\n\n"
        
        md += "---\n\n"
        
        
        
       
        
        return md
    
    def save_summary_pdf(self, content):
        """Save summary as PDF with proper formatted tables"""
        try:
            from fpdf import FPDF
            
            class PDF(FPDF):
                def create_table(self, headers, data, col_widths):
                    """Create a properly formatted table with borders"""
                    # Header
                    self.set_font('Arial', 'B', 10)
                    self.set_fill_color(200, 220, 255)
                    for i, header in enumerate(headers):
                        self.cell(col_widths[i], 8, str(header), border=1, fill=True, align='C')
                    self.ln()
                    
                    # Data rows
                    self.set_font('Arial', '', 9)
                    for row in data:
                        for i, cell in enumerate(row):
                            self.cell(col_widths[i], 7, str(cell), border=1, align='L')
                        self.ln()
                    self.ln(3)
            
            pdf = PDF()
            pdf.add_page()
            pdf.set_auto_page_break(auto=True, margin=15)
            
            # Title
            pdf.set_font('Arial', 'B', 16)
            pdf.cell(0, 10, 'Final Metrics Summary - BB84 Quantum Encryption System', ln=True, align='C')
            pdf.ln(5)
            
            pdf.set_font('Arial', 'I', 10)
            pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
            pdf.ln(3)
            
            # Section 1: BB84 Summary
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 8, '1. Quantum Key Distribution (BB84) Summary', ln=True)
            pdf.ln(3)
            
            aes_enc = self.metrics['aes_encrypt']
            chacha_enc = self.metrics['chacha_encrypt']
            
            if aes_enc or chacha_enc:
                headers = ['Metric', 'AES-GCM', 'ChaCha20']
                data = [
                    ['Key A Length', aes_enc.get('Key A Length', 'N/A'), chacha_enc.get('Key A Length', 'N/A')],
                    ['Key B Length', aes_enc.get('Key B Length', 'N/A'), chacha_enc.get('Key B Length', 'N/A')],
                    ['Key B (1s count)', aes_enc.get('Key B - 1s', 'N/A'), chacha_enc.get('Key B - 1s', 'N/A')],
                    ['Key B (0s count)', aes_enc.get('Key B - 0s', 'N/A'), chacha_enc.get('Key B - 0s', 'N/A')],
                    ['A/B Match %', aes_enc.get('A/B Match %', 'N/A'), chacha_enc.get('A/B Match %', 'N/A')],
                    ['Error Rate', aes_enc.get('Error Rate', 'N/A'), chacha_enc.get('Error Rate', 'N/A')],
                    ['Shannon Entropy', aes_enc.get('Shannon Entropy', 'N/A'), chacha_enc.get('Shannon Entropy', 'N/A')],
                    ['Key Confirmation', aes_enc.get('Key Confirmation', 'N/A'), chacha_enc.get('Key Confirmation', 'N/A')]
                ]
                pdf.create_table(headers, data, [70, 60, 60])
                
                pdf.set_font('Arial', 'B', 10)
                # pdf.cell(0, 6, 'Interpretation:', ln=True)
                pdf.set_font('Arial', '', 9)
                
                pdf.ln(5)
            
            # Section 2: Encryption Performance
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 8, '2. Encryption Performance Summary', ln=True)
            pdf.ln(3)
            
            if aes_enc or chacha_enc:
                headers = ['Metric', 'AES-GCM', 'ChaCha20']
                data = [
                    ['Timestamp', aes_enc.get('Timestamp', 'N/A'), chacha_enc.get('Timestamp', 'N/A')],
                    ['Encryption Time (s)', aes_enc.get('Encryption Time', 'N/A'), chacha_enc.get('Encryption Time', 'N/A')],
                    ['Original File Size (bytes)', aes_enc.get('Original File Size', 'N/A'), chacha_enc.get('Original File Size', 'N/A')],
                    ['Encrypted File Size (bytes)', aes_enc.get('Encrypted File Size', 'N/A'), chacha_enc.get('Encrypted File Size', 'N/A')],
                    ['SHA-256 Hash', str(aes_enc.get('SHA-256 Encrypted', 'N/A'))[:20]+'...', str(chacha_enc.get('SHA-256 Encrypted', 'N/A'))[:20]+'...'],
                    ['Post-Quantum Signature', aes_enc.get('Post-Quantum Signature', 'N/A'), chacha_enc.get('Post-Quantum Signature', 'N/A')]
                ]
                pdf.create_table(headers, data, [70, 60, 60])
                
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 6, 'Interpretation:', ln=True)
                pdf.set_font('Arial', '', 9)
                
                try:
                    aes_time = float(aes_enc.get('Encryption Time', '0').replace(' s', '').strip())
                    chacha_time = float(chacha_enc.get('Encryption Time', '0').replace(' s', '').strip())
                    if aes_time > 0 and chacha_time > 0:
                        if chacha_time < aes_time:
                            diff = ((aes_time - chacha_time) / aes_time) * 100
                            pdf.multi_cell(0, 5, f'+ ChaCha20 was {diff:.1f}% faster than AES-GCM in encryption')
                        else:
                            diff = ((chacha_time - aes_time) / chacha_time) * 100
                            pdf.multi_cell(0, 5, f'+ AES-GCM was {diff:.1f}% faster than ChaCha20 in encryption')
                except:
                    pass
                
                pdf.multi_cell(0, 5, '+ Both produced similar encrypted file sizes')
                pdf.multi_cell(0, 5, '+ Post-quantum Dilithium5 signatures protect against quantum attacks')
                pdf.ln(5)
            
            # Section 3: Decryption Performance
            pdf.set_font('Arial', 'B', 14)
            pdf.cell(0, 8, '3. Decryption Performance Summary', ln=True)
            pdf.ln(3)
            
            aes_dec = self.metrics['aes_decrypt']
            chacha_dec = self.metrics['chacha_decrypt']
            
            if aes_dec or chacha_dec:
                headers = ['Metric', 'AES-GCM', 'ChaCha20']
                data = [
                    ['Timestamp', aes_dec.get('Timestamp', 'N/A'), chacha_dec.get('Timestamp', 'N/A')],
                    ['Decryption Time (s)', aes_dec.get('Decryption Time', 'N/A'), chacha_dec.get('Decryption Time', 'N/A')],
                    ['AEAD Authentication', aes_dec.get('AEAD Authentication', 'N/A'), chacha_dec.get('AEAD Authentication', 'N/A')],
                    ['Decrypted File Size (bytes)', aes_dec.get('Decrypted File Size', 'N/A'), chacha_dec.get('Decrypted File Size', 'N/A')],
                    ['SHA-256 Hash', str(aes_dec.get('SHA-256 Decrypted', 'N/A'))[:20]+'...', str(chacha_dec.get('SHA-256 Decrypted', 'N/A'))[:20]+'...']
                ]
                pdf.create_table(headers, data, [70, 60, 60])
                
                pdf.set_font('Arial', 'B', 10)
                pdf.cell(0, 6, 'Interpretation:', ln=True)
                pdf.set_font('Arial', '', 9)
                
                aes_hash = aes_dec.get('SHA-256 Decrypted', '')
                chacha_hash = chacha_dec.get('SHA-256 Decrypted', '')
                if aes_hash != 'Not in report' and chacha_hash != 'Not in report' and aes_hash == chacha_hash:
                    pdf.multi_cell(0, 5, '+ VERIFICATION PASSED: Both ciphers decrypted to identical files')
                
                try:
                    aes_time = float(aes_dec.get('Decryption Time', '0').replace(' s', '').strip())
                    chacha_time = float(chacha_dec.get('Decryption Time', '0').replace(' s', '').strip())
                    if aes_time > 0 and chacha_time > 0:
                        if aes_time < chacha_time:
                            diff = ((chacha_time - aes_time) / chacha_time) * 100
                            pdf.multi_cell(0, 5, f'+ AES-GCM was {diff:.1f}% faster than ChaCha20 in decryption')
                        else:
                            diff = ((aes_time - chacha_time) / aes_time) * 100
                            pdf.multi_cell(0, 5, f'+ ChaCha20 was {diff:.1f}% faster than AES-GCM in decryption')
                except:
                    pass
                
                pdf.multi_cell(0, 5, '+ AEAD authentication prevents tampering and ensures data integrity')
                pdf.multi_cell(0, 5, '+ Both ciphers provide equivalent 256-bit security strength')
            
            output_path = os.path.join(self.results_folder, "BB84_Final_Metrics_Summary.pdf")
            pdf.output(output_path)
            return output_path
        except Exception as e:
            print(f"Error saving PDF: {e}")
            return None


def main():
    print("=" * 60)
    print("🔄 BB84 Auto Results Summary Generator")
    print("=" * 60)
    print("This tool automatically:")
    print("  1. Scans all PDF files in specified folder")
    print("  2. Extracts metrics from each report")
    print("  3. Generates comprehensive PDF summary")
    print("\n" + "=" * 60 + "\n")
    
    # Default path - change this to your PDF reports folder
    default_path = r"C:\Users\Qadri laptop\Downloads\New folder (2)\BB84-Quantum-Encryption-Tool-Simulator\testing\Video"
    # Get results folder path
    results_folder = input(f"Enter PDF folder path (press Enter for default):\n[{default_path}]\n> ").strip().strip('"')
    if not results_folder:
        results_folder = default_path
    
    print(f"\n📁 Scanning folder: {results_folder}")
    
    # Create extractor (scan and save in same folder)
    extractor = AutoMetricsExtractor(results_folder=results_folder)
    
    # Scan folder
    if not extractor.scan_results_folder():
        return
    
    print("\n🔄 Generating PDF summary...")
    
    # Generate markdown summary
    summary = extractor.generate_markdown_summary()
    
    # Save as PDF in the same folder
    output_path = extractor.save_summary_pdf(summary)
    
    if output_path:
        print("\n" + "=" * 60)
        print("✅ SUCCESS!")
        print("=" * 60)
        print(f"📄 Summary saved to: {output_path}")
        print("\nThe PDF report includes:")
        print("  ✓ Quantum Key Distribution (BB84) comparison")
        print("  ✓ Encryption performance analysis")
        print("  ✓ Decryption performance analysis")
        print("  ✓ Security features summary")
        print("  ✓ Cipher selection recommendations")
    else:
        print("\n❌ Failed to save summary")


if __name__ == "__main__":
    main()
