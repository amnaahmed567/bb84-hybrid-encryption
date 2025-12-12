"""
Generate PDF from UPGRADED_FRAMEWORK_DOCUMENTATION.md
Uses fpdf2 library for PDF generation with proper Unicode handling
"""

from fpdf import FPDF
import re

def clean_text(text):
    """Replace Unicode characters with ASCII equivalents"""
    replacements = {
        '\u2022': '-',  # bullet
        '\u2013': '-',  # en dash
        '\u2014': '--', # em dash
        '\u2018': "'",  # left single quote
        '\u2019': "'",  # right single quote
        '\u201c': '"',  # left double quote
        '\u201d': '"',  # right double quote
        '\u2192': '->',  # right arrow
        '\u21d2': '=>',  # double arrow
        '\u2190': '<-',  # left arrow
        '\u2194': '<->', # bidirectional arrow
        '\u2502': '|',  # box vertical
        '\u250c': '+',  # box top-left
        '\u2510': '+',  # box top-right
        '\u2514': '+',  # box bottom-left
        '\u2518': '+',  # box bottom-right
        '\u251c': '+',  # box vertical right
        '\u2524': '+',  # box vertical left
        '\u252c': '+',  # box horizontal down
        '\u2534': '+',  # box horizontal up
        '\u253c': '+',  # box cross
        '\u2500': '-',  # box horizontal
        '\u2550': '=',  # box double horizontal
        '\u2551': '|',  # box double vertical
        '\u2554': '+',  # box double top-left
        '\u2557': '+',  # box double top-right
        '\u255a': '+',  # box double bottom-left
        '\u255d': '+',  # box double bottom-right
        '\u2560': '+',  # box double vertical right
        '\u2563': '+',  # box double vertical left
        '\u2566': '+',  # box double horizontal down
        '\u2569': '+',  # box double horizontal up
        '\u256c': '+',  # box double cross
        '\u25bc': 'v',  # down triangle
        '\u25b6': '>',  # right triangle
        '\u25c0': '<',  # left triangle
        '\u25b2': '^',  # up triangle
        '\u2713': '[OK]',  # checkmark
        '\u2717': '[X]',   # X mark
        '\u2714': '[OK]',  # heavy checkmark
        '\u2718': '[X]',   # heavy X mark
        '✅': '[OK]',
        '❌': '[X]',
        '→': '->',
        '←': '<-',
        '↓': 'v',
        '↑': '^',
    }
    for unicode_char, ascii_char in replacements.items():
        text = text.replace(unicode_char, ascii_char)
    return text

class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
        
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Upgraded Quantum-Classical Hybrid Encryption Framework', 0, 1, 'C')
        self.ln(5)
        
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')
        
    def chapter_title(self, title):
        self.set_font('Arial', 'B', 14)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, clean_text(title), 0, 1, 'L', 1)
        self.ln(4)
        
    def chapter_subtitle(self, subtitle):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 8, clean_text(subtitle), 0, 1, 'L')
        self.ln(2)
        
    def chapter_body(self, body):
        self.set_font('Arial', '', 10)
        self.multi_cell(0, 5, clean_text(body))
        self.ln()
        
    def add_code_block(self, code):
        self.set_font('Courier', '', 9)
        self.set_fill_color(245, 245, 245)
        lines = code.split('\n')
        for line in lines:
            line = clean_text(line)
            # Handle long lines
            if len(line) > 90:
                self.multi_cell(0, 4, line, 0, 'L', 1)
            else:
                self.cell(0, 4, line, 0, 1, 'L', 1)
        self.ln(2)
        
    def add_table_row(self, data, header=False):
        if header:
            self.set_font('Arial', 'B', 9)
            self.set_fill_color(200, 220, 255)
        else:
            self.set_font('Arial', '', 9)
            self.set_fill_color(240, 240, 240)
        
        col_widths = [40, 35, 35, 80]  # Adjust based on table structure
        if len(data) == 2:
            col_widths = [60, 120]
        elif len(data) == 3:
            col_widths = [50, 60, 80]
        
        for i, item in enumerate(data):
            if i < len(col_widths):
                self.cell(col_widths[i], 6, clean_text(item[:50]), 1, 0, 'L', 1)
        self.ln()

def parse_markdown_to_pdf(md_file, pdf_file):
    pdf = PDF()
    pdf.add_page()
    
    with open(md_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    lines = content.split('\n')
    i = 0
    in_code_block = False
    code_buffer = []
    in_table = False
    
    while i < len(lines):
        line = lines[i]
        
        # Code blocks
        if line.startswith('```'):
            if in_code_block:
                # End of code block
                pdf.add_code_block('\n'.join(code_buffer))
                code_buffer = []
                in_code_block = False
            else:
                # Start of code block
                in_code_block = True
            i += 1
            continue
            
        if in_code_block:
            code_buffer.append(line)
            i += 1
            continue
        
        # Headers
        if line.startswith('# '):
            pdf.add_page()
            pdf.chapter_title(line[2:])
        elif line.startswith('## '):
            pdf.chapter_title(line[3:])
        elif line.startswith('### '):
            pdf.chapter_subtitle(line[4:])
        elif line.startswith('#### '):
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 6, line[5:], 0, 1)
            pdf.ln(1)
        
        # Horizontal rules
        elif line.startswith('---'):
            pdf.ln(2)
            pdf.set_draw_color(200, 200, 200)
            pdf.line(10, pdf.get_y(), 200, pdf.get_y())
            pdf.ln(2)
        
        # Tables
        elif '|' in line and line.strip().startswith('|'):
            # Table row
            cells = [cell.strip() for cell in line.split('|')[1:-1]]
            if cells:
                # Check if header separator
                if all(re.match(r'^[-:]+$', cell) for cell in cells):
                    i += 1
                    continue
                # Check if first row (header)
                if i > 0 and '|' not in lines[i-1]:
                    pdf.add_table_row(cells, header=True)
                else:
                    pdf.add_table_row(cells, header=False)
        
        # Bullet points
        elif line.startswith('- ') or line.startswith('* '):
            pdf.set_font('Arial', '', 10)
            # Remove markdown formatting
            text = line[2:].replace('**', '').replace('`', '')
            # Replace bullet with ASCII and clean special chars
            pdf.multi_cell(0, 5, clean_text(f"  - {text}"))
        
        # Checkmarks - convert to ASCII
        elif line.strip().startswith('✅') or line.strip().startswith('❌'):
            pdf.set_font('Arial', '', 10)
            text = line.strip().replace('**', '').replace('`', '')
            # Clean all special characters
            pdf.multi_cell(0, 5, clean_text(f"  {text}"))
        
        # Regular paragraphs
        elif line.strip():
            # Remove markdown formatting
            text = line.replace('**', '').replace('`', '').replace('*', '')
            if not line.startswith('#'):
                pdf.set_font('Arial', '', 10)
                pdf.multi_cell(0, 5, clean_text(text))
        
        # Empty lines
        else:
            if i > 0 and lines[i-1].strip():
                pdf.ln(2)
        
        i += 1
    
    # Output PDF
    pdf.output(pdf_file)
    print(f"✅ PDF generated successfully: {pdf_file}")

if __name__ == '__main__':
    md_file = 'UPGRADED_FRAMEWORK_DOCUMENTATION.md'
    pdf_file = 'UPGRADED_FRAMEWORK_DOCUMENTATION.pdf'
    
    try:
        parse_markdown_to_pdf(md_file, pdf_file)
    except Exception as e:
        print(f"❌ Error generating PDF: {e}")
        import traceback
        traceback.print_exc()
