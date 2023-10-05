import csv
import sys
import requests
import base64
import re
from colorama import Fore
from datetime import datetime
import time

def api_read():
    with open('api_config.conf', 'r') as api_file:
        api_key = api_file.read()
        return api_key

def readCSV():
    column = []

    with open('input.csv', 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        for row in csvreader:
            column.extend(row)
            
    return column

def pass_through_virus_total(values, apikey):
    encodedURL = base64.urlsafe_b64encode(values.encode()).decode().strip("=") #This is just how VT wants their URLs :/ Causes bugs to format this way for some URLs
    url = f"https://www.virustotal.com/api/v3/urls/{encodedURL}"
    headers = {"accept": "application/json",
               "x-apikey": apikey}
    
    response = requests.get(url, headers=headers)
    status_code = response.status_code
    if status_code != 200:
        return f"!!! HTTP request failed with status code {status_code} to URL: "

    return response.text

'''
The script begins to fail by about the 140th value in the csv (Status code 429). Unsure if this is due to limitations of
the VT API key, or if its just general rate limiting.
EDIT: even with the buffer it starts to rate limit again at 240. Additional buffer required.

It seems like it's just rate limiting. I'm going to add a 2 second buffer after the 100th search.

It should be noted that on a personal license, we will be getting status code 429 after the 500th search.
'''


def url_search():
    input_values = readCSV()

    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name = f"results_url_{current_datetime}.txt"
    errors = []

    with open(file_name, 'w') as results_file:
        iteration = 0
        for i in input_values:
            iteration += 1
            while iteration > 100:
                while iteration > 200:
                    time.sleep(2)
                time.sleep(2)
                break
            result = pass_through_virus_total(i, api_read())

            if "HTTP request failed" in result:
                print(Fore.YELLOW + result + f'{i}')
                results_file.write(result + f'{i}' + '\n')
                errors.extend(result)
            else:
                pattern = r'\b(phishing|malicious)\b'
                matches = re.findall(pattern, result, re.IGNORECASE)

                if matches:
                    print(Fore.RED + f"{i} has been flagged as malicious by >=1 vendor")
                    results_file.write(f"{i} has been flagged as malicious by >=1 vendor" + '\n')
                else:
                    print(Fore.GREEN + f"{i} has no vendors flagging this as malicious")
                    results_file.write(f"{i} has no vendors flagging this as malicious" + '\n')

        print(f"------------------------------------------\nThe folowing errors have occured:")
        for i in errors:
            print(errors[i] + '\n')

def main():
    try:
        if sys.argv[1] == '-u':
            url_search()
    except IndexError:
        print("Flag not recognised")
        
main()
