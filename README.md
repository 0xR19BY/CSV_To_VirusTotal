# CSV-to-VirusTotal

For converting a column of data within a CSV and passing it through VirusTotal for an abstracted idea of if a list of domains are flagged as malicious.

The data that you are given is ***NOT*** a comprehensive overview of the potential impact; just a brief indicator of if a given value may be malicious

# Dependencies
 - Install dependencies with ```pip install -r requirements.txt```

## Usage/Examples

Within the directory, there is an input.csv - this is where the data that you wish to test lives. Data should only occupy the **A** column and can go as far down as your API licensing allows. Below is an example:

|         | A          |  
|---------|------------|
| **1**   | ExampleURL |
| **2**   | ExampleURL |   
| **3**   | ExampleURL | 
| **4**   | ExampleURL |  
| **5**   | ExampleURL |   
| **...** | **...**    |  

Usage:
 - Put your API key into api_config.conf
    - Command: '''python csv_to_vt.py -u'''
 - Results will be displayed in your terminal and also be written to a .txt file under name results_*

### Potential Bugs
 -  a lot of 404 errors for values.
