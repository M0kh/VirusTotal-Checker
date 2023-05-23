import vt
import os
import time
import sys
import csv
from colorama import Fore

def clrscr():
    #Check if Operating System is Mac and Linux or Windows
   if os.name == 'posix':
      _ = os.system('clear')
   else:
    #Else Operating System is Windows (os.name = nt)
      _ = os.system('cls')

def Key():
    clrscr()
    global client
    try: 
        print('Enter your Virustotal API key:\n')
        APIKey = input()
        if len(APIKey) < 50:
            print('\nInvalid Key\n')
            time.sleep(1)
            Key()
        else:
            client = vt.Client(APIKey)
            clrscr()
            options()
    except KeyboardInterrupt:
        Key()

def URLS():
    clrscr()
    try:
        print('Enter the path to the CSV or TXT file that contains the URLs (If the file is in the same path as the script, just insert the file name)\n')
        FilePath = input()
        URLs = open(FilePath, 'r', encoding='utf-8-sig')
        clrscr()
    except OSError as e:
        print("Unable to open " + FilePath + "\n", file=sys.stderr)
        options()
    except KeyboardInterrupt:
        options()
    header = ['URL', 'Malicious', 'Suspicious', 'Timeout', 'Undetected', 'Harmless']
    with open('URL Output.csv', 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
    for URLLoop in URLs:
        print("Results for: " + URLLoop)
        url_id = vt.url_id(URLLoop)
        url = client.get_object("/urls/{}", url_id)
        res=str((url.last_analysis_stats))
        result = res.split(',')
        #print(result[0].replace("'{harmless'", 'Harmless'))
    
        if str((result[1].split(':')[1])) == " 0":
            print(Fore.GREEN + str(result[1].replace(" 'malicious'", "Not Malicious")))
        else:
            print(Fore.RED + str(result[1].replace(" 'malicious'", "Malicious")))
        
        if str((result[2].split(':')[1])) == " 0":
            print(Fore.GREEN + str(result[2].replace(" 'suspicious'", "Not Suspicious")))
            print(Fore.RESET + "")
        else:
            print(Fore.YELLOW + str(result[2].replace(" 'suspicious'", "Suspicious")))
            print(Fore.RESET + "")
        #print(result[3].replace(" 'undetected'", 'Undetected'))
        #print(result[4].replace(" 'timeout'", 'Timeout').replace('}', ''))
        print("\n")
        with open('URL Output.csv', 'a', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            data = [URLLoop, result[1].split(':')[1], result[2].split(':')[1], result[4].split(':')[1].replace("}", ""), result[3].split(':')[1], result[0].split(':')[1]]
            writer.writerow(data)
        time.sleep(16)
    print("Done")
    time.sleep(2)
    options()

def Files():
    clrscr()
    try:
        print('Enter the path to the CSV or TXT file that contains the hashes (If the file is in the same path as the script, just insert the file name)\n')
        FilePath = input()
        Files = open(FilePath, 'r', encoding='utf-8-sig')
        clrscr()
    except OSError as e:
        print("Unable to open " + FilePath + "\n", file=sys.stderr)
        options()
    except KeyboardInterrupt:
        options()
    header = ['Hash', 'File Type', 'Malicious', 'Suspicious', 'Confirmed-Timeout', 'Timeout', 'Undetected', 'Failure', 'Type-Unsupported', 'Harmless']
    with open('Hash Output.csv', 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header) 
    for FileLoop in Files:
        print("Results for: " + FileLoop)
        FileLoop = FileLoop.rstrip('\r\n') 
        FileLoopURL = '/files/'+FileLoop
        file = client.get_object(FileLoopURL)
        filetype = str(file.type_tag)
        res=str((file.last_analysis_stats))
        result = res.split(',')
        #print(result[0].replace("'{harmless'", 'Harmless'))
        #print(result[1].replace("'{type-unsupported'", 'Type-Unsupported'))    
        if str((result[6].split(':')[1])) == " 0":
            print(Fore.GREEN + str(result[6].replace(" 'malicious'", "Not Malicious")))
        else:
            print(Fore.RED + str(result[6].replace(" 'malicious'", "Malicious")))
        
        if str((result[2].split(':')[1])) == " 0":
            print(Fore.GREEN + str(result[2].replace(" 'suspicious'", "Not Suspicious")))
        else:
            print(Fore.YELLOW + str(result[2].replace(" 'suspicious'", "Suspicious")))
        
        #print(result[3].replace(" 'confirmed-timeout'", 'Confirmed-Timeout').replace('}', ''))
        #print(result[4].replace(" 'timeout'", 'Timeout').replace('}', ''))
        #print(result[5].replace(" 'failure'", 'Failure').replace('}', ''))
        #print(result[7].replace(" 'undetected'", 'Undetected').replace('}', ''))
        print(Fore.RESET + "File Type: " + filetype)
        print("\n")
        with open('Hash Output.csv', 'a', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            data = [FileLoop, filetype, result[6].split(':')[1], result[2].split(':')[1], result[3].split(':')[1], result[4].split(':')[1], result[7].split(':')[1].replace("}", ""), result[5].split(':')[1], result[1].split(':')[1], result[0].split(':')[1]]
            writer.writerow(data)
        time.sleep(16)
    print("Done")
    time.sleep(2)
    options()

def options():
    clrscr()
    try:
        print("Choose an option\n")
        print("1- Get information about URLs")
        print("2- Get information about Files")
        print("3- Exit\n")
        print("Type the number of your choice:\n")
        choice = input()
        if choice == "1":
            URLS()
        elif choice == "2":
            Files()
        elif choice == "3":
            exit()
        else:
            print("Error: Wrong Input, Please Reselect")
            options()
    except KeyboardInterrupt:
        options()
Key()
