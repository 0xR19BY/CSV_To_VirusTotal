import csv
import sys
import requests
import base64
import re
from colorama import Fore
from datetime import datetime
import time
import json

def api_read():
    with open('api_config.conf', 'r', encoding="utf-8") as api_file:
        api_key = api_file.read()
        return api_key

def readCSV():
    column = []

    with open('input.csv', 'r', encoding="utf-8") as csvfile:
        csvreader = csv.reader(csvfile)

        for row in csvreader:
            column.extend(row)
            
    return column

def check_value(value):
    hash_pattern = r'^[0-9a-fA-F]+$'
    ipv4_pattern = r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'

    hash_matches = re.findall(hash_pattern, value, re.IGNORECASE)
    ipv4_matches = re.findall(ipv4_pattern, value, re.IGNORECASE)
    url_matches = re.findall(url_pattern, value, re.IGNORECASE)

    if hash_matches:
        return {value : 'hash'}
    elif ipv4_matches:
        return {value: 'ipv4'}
    elif isinstance(value, str): #regex can vary too much - this is now a test
        return {value : 'url'}
    else:
        print("!value panic! exiting")
        exit()
    
def pass_through_virus_total(values, apikey):
    #Searches if it is a URL
    if check_value(values) == {values : 'url'}: #This took way too much brain power
        encodedURL = base64.urlsafe_b64encode(values.encode()).decode().strip("=") #This is just how VT wants their URLs :/ Causes bugs to format this way for some URLs
        url = f"https://www.virustotal.com/api/v3/urls/{encodedURL}"
        headers = {"accept": "application/json",
                "x-apikey": apikey}
        
        response = requests.get(url, headers=headers)
        status_code = response.status_code
        if status_code != 200:
            return f"!!! HTTP request failed with status code {status_code} to URL: "

        return response.text
    elif check_value(values) == {values : 'ipv4'}:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{values}"
        headers = {"accept": "application/json",
                "x-apikey": apikey}
        
        response = requests.get(url, headers=headers)
        status_code = response.status_code
        if status_code != 200:
            return f"!!! HTTP request failed with status code {status_code} to IPv4 address: "

        return response.text
    elif check_value(values) == {values : 'hash'}:
        url = f"https://www.virustotal.com/api/v3/files/{values}"
        headers = {"accept": "application/json",
                "x-apikey": apikey}
        
        response = requests.get(url, headers=headers)
        status_code = response.status_code
        
        if status_code != 200:
            return f"!!! HTTP request failed with status code {status_code} to IPv4 address: "

        return response.text

'''
The script begins to fail by about the 140th value in the csv (Status code 429). Unsure if this is due to limitations of
the VT API key, or if its just general rate limiting.
EDIT: even with the buffer it starts to rate limit again at 240. Additional buffer required.

It seems like it's just rate limiting. I'm going to add a 2 second buffer after the 100th search.

It should be noted that on a personal license, we will be getting status code 429 after the 500th search.
'''

def search(): 
    input_values = readCSV()

    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"results_url_{current_datetime}.csv"
    errors = []

    with open(file_name, 'w', encoding="utf-8") as results_file:
        header = 'Object, No. Malicious, No. Suspicious \n'
        results_file.write(header)

        iteration = 0
        for i in input_values:
            iteration += 1
            while iteration > 100:
                while iteration > 200:
                    time.sleep(2)
                time.sleep(2)
                break
            result = pass_through_virus_total(i, api_read())

            if result == None:
                print(Fore.BLUE + "Error: No data to analyse!!!")
            elif "HTTP request failed" in result:
                print(Fore.YELLOW + result + f'{i}')
                results_file.write(f'{i},ERROR,ERROR\n')
                errors.extend(result)

            else:
                data = json.loads(result)

                #Will extract the last_analysis_stats field
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']
                #To access individual fields
                malicious = last_analysis_stats['malicious']
                suspicious = last_analysis_stats['suspicious']

                if malicious > 0 or suspicious > 0:
                    print(Fore.RED + f"{i} flagged as malicious by {malicious} vendors and suspicious by {suspicious} vendors")
                    results_file.write(f"{i},{malicious},{suspicious} \n")
                else:
                    print(Fore.GREEN + f"{i} not flagged as malicious or suspicious")
                    results_file.write(f"{i},N/A,N/A\n")

        print("------------------------------------------\nThe following errors have occurred:")
        for i in errors:
            print(errors[i] + '\n')

def main():
    try:
        if sys.argv[1] == '-s':
            search()
        #Looking for API key
        elif sys.argv[1] == '-a':
            if sys.argv[2] != '':
                with open('api_config.conf', 'w', encoding="utf-8") as api_edit:
                    api_edit.write(sys.argv[2])
            elif sys.argv == None:
                print('API Key not supplied')

    except IndexError:
        print("COMMANDS:\n > -u: URL Search\n > -a API_KEY: Input your API key")
        
main()