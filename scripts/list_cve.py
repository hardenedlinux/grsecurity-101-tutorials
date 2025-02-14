#!/usr/bin/env python3

# List CVE and affected version based on the json file from Google KernelCTF

import os
import json
import glob


def process_json_file(filepath):


    try:
        with open(filepath, 'r', encoding='utf-8') as file:
            data = json.load(file)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON in file {filepath}: {e}")
        return
    except Exception as e:
        print(f"Could not read file {filepath}: {e}")
        return


    # Get the value for key 'cdf'
    if 'vulnerability' in data:
        print("Vulnerability:", data['vulnerability']['cve'])
    else:
        print("Key 'cve' not found")

    # Get the value for key 'affe'
    if 'vulnerability' in data:
        print("Affected versions:", data['vulnerability']['affected_versions'])
    else:
        print("Key 'affected_versions' not found")

    print('-' * 40)


def main():

    # Use glob to search for all .json files in the current directory
    json_files = glob.glob("**/*.json", recursive=True)

    if not json_files:
        print("No JSON files found in the current directory.")
        return

    for filepath in json_files:
        process_json_file(filepath)

if __name__ == "__main__":
    main()
