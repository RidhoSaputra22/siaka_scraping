import json
import csv
from datetime import datetime
import os

def save_to_json(data, filename, output_dir='data'):
    """Save data to JSON file"""
    filepath = os.path.join(output_dir, filename)
    os.makedirs(output_dir, exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print(f"Data saved to {filepath}")
    return filepath

def save_to_csv(data, filename, output_dir='data'):
    """Save data to CSV file"""
    if not data:
        print("No data to save")
        return None
        
    filepath = os.path.join(output_dir, filename)
    os.makedirs(output_dir, exist_ok=True)
    
    # Assuming data is a list of dictionaries
    if isinstance(data, list) and len(data) > 0:
        fieldnames = data[0].keys()
        
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data)
        
        print(f"Data saved to {filepath}")
        return filepath
    else:
        print("Data format not suitable for CSV export")
        return None

def get_timestamp():
    """Get current timestamp for file naming"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")

def validate_response(response):
    """Validate HTTP response"""
    if response.status_code != 200:
        raise Exception(f"HTTP Error {response.status_code}: {response.reason}")
    return True

def clean_text(text):
    """Clean and normalize text data"""
    if text:
        return text.strip().replace('\n', ' ').replace('\r', ' ')
    return ''

def parse_jadwal_row(row_element):
    """Parse a single jadwal row element"""
    # This will be implemented based on actual HTML structure
    # when we analyze the jadwal page after login
    pass