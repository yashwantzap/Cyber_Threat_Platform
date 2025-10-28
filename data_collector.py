import requests
import json
import os
import glob
from datetime import date
from collections import defaultdict

# --- Configuration for Rich Data Collection ---
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_DIR = "data"

def ensure_directory_exists(directory):
    """Ensures the specified directory exists."""
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Created directory: {directory}")

def delete_old_data_files(directory):
    """Deletes all JSON files in the specified directory."""
    print(f"Checking for old data files in '{directory}'...")
    file_pattern = os.path.join(directory, '*.json')
    files_to_delete = glob.glob(file_pattern)
    
    if not files_to_delete:
        print("No old data files found. Proceeding with new data collection.")
        return

    print(f"Found {len(files_to_delete)} old data files. Deleting...")
    for file_path in files_to_delete:
        try:
            os.remove(file_path)
            print(f"  - Deleted {os.path.basename(file_path)}")
        except OSError as e:
            print(f"Error: {file_path} - {e.strerror}")
    print("Old data files deleted.")

def fetch_threat_data(url):
    """Fetches data from a given URL."""
    try:
        print(f"Fetching data from {url}...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        print("Data fetched successfully.")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return None

def collect_rich_data():
    """Collects rich cybersecurity data from multiple sources."""
    print("Collecting rich data...")
    
    # Fetch from CISA KEV
    cisa_data = fetch_threat_data(CISA_KEV_URL)
    if not cisa_data:
        print("Failed to fetch CISA data.")
        return None

    if 'vulnerabilities' not in cisa_data:
        print("No vulnerabilities found in CISA data.")
        return None

    rich_threat_data = defaultdict(dict)
    
    vulnerabilities = cisa_data.get('vulnerabilities', [])
    print(f"Processing {len(vulnerabilities)} vulnerabilities...")
    
    for item in vulnerabilities:
        cve_id = item.get('cveID')
        if cve_id:
            rich_threat_data[cve_id] = {
                'cve_info': item,
                'additional_context': {}
            }
    
    print(f"Collected data for {len(rich_threat_data)} CVEs.")
    return dict(rich_threat_data)

def save_rich_data_to_file(data, directory=DATA_DIR):
    """Saves the collected rich data to a JSON file."""
    ensure_directory_exists(directory)
    
    today = date.today().isoformat()
    filename = os.path.join(directory, f"rich_threat_data_{today}.json")
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4, default=str)
        print(f"Rich data saved to {filename}")
        return filename
    except Exception as e:
        print(f"Error saving data to {filename}: {e}")
        return None

def main():
    """Main function to run the data collection process."""
    # Ensure data directory exists before trying to delete files
    ensure_directory_exists(DATA_DIR)
    
    # Step 1: Delete any old data files to ensure a fresh start
    delete_old_data_files(DATA_DIR)
    
    # Step 2: Proceed with the data collection
    rich_data = collect_rich_data()
    
    if rich_data:
        saved_file = save_rich_data_to_file(rich_data)
        if saved_file:
            print("Data collection completed successfully.")
        else:
            print("Failed to save data.")
    else:
        print("Data collection failed.")

if __name__ == "__main__":
    main()
