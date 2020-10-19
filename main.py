#!/home/noname/PycharmProjects/pythonProject/venv/bin/python
# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


import requests
import sys
from json2html import *

try:
    with open( '/etc/abuseipdb/secret.conf' ) as f:
        key = f.read().strip()
except FileNotFoundError as err:
    sys.exit( '"secret" file not found' )

categories = {
        1: 'DNS Compromise',
        2: 'DNS Poisoning',
        3: 'Fraud_Orders',
        4: 'DDoS_Attack',
        5: 'FTP Brute-Force',
        6: 'Ping of Death',
        7: 'Phishing',
        8: 'Fraud VoIP',
        9: 'Open Proxy',
        10: 'Web Spam',
        11: 'Email Spam',
        12: 'Blog Spam',
        13: 'VPN IP',
        14: 'Port Scan',
        15: 'Hacking',
        16: 'SQL Injection',
        17: 'Spoofing',
        18: 'Brute-Force',
        19: 'Bad Web Bot',
        20: 'Exploited Host',
        21: 'Web App Attack',
        22: 'SSH',
        23: 'IoT Targeted',
}

def request_ip( ipAddress, maxAgeInDays = 30, verbose = None ):
    endpoint = 'https://api.abuseipdb.com/api/v2/check'

    params = {
        "ipAddress": ipAddress,
        "maxAgeInDays": maxAgeInDays,
        "verbose": verbose
    }

    headers = {
        "Key": key,
        "Accept": "application/json"
    }

    r = requests.request('GET', endpoint, headers=headers, params=params)
    return r.json()

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    import argparse
    from pprint import pprint

    my_parser = argparse.ArgumentParser(description='Check IP reputation on AbuseIPDB')
    my_parser.add_argument( '-v', '--verbose', action="store_true", help = "default = False" )
    my_parser.add_argument( "-m", "--maxAgeInDays", metavar="days", type=int, help = "default = 30 days",  )
    my_group = my_parser.add_mutually_exclusive_group(required=True)
    my_group.add_argument( '-i', '--ip_address', metavar = 'ip_address', nargs='+', type = str, help = 'The ip address(es) to check on AbuseIPDB' )
    my_group.add_argument( "-f", "--file", metavar="filename", type=str, help="filename with ip list to check" )

    args = my_parser.parse_args()
    verbose = args.verbose if args.verbose == True else None
    maxAgeInDays = args.maxAgeInDays if args.maxAgeInDays else 30

    if args.file:
        try:
            with open( args.file ) as f:
                ip_to_check = [ ip.strip() for ip in f.readlines() ]
        except FileNotFoundError as err:
            print( err )
            sys.exit()
    else:
        ip_to_check = [ ip for ip in args.ip_address ]

    results = []
    for ip in ip_to_check:
        res = request_ip( ip, maxAgeInDays, verbose )
        if 'data' in res:
            data = res[ 'data' ]
            flg = '<img src = "https://www.countryflags.io/{}/flat/32.png">'.format( data[ 'countryCode' ] )
            item = {
                    'ipAddress' : data[ 'ipAddress' ],
                    'abuseConfidenceScore' : data[ 'abuseConfidenceScore' ],
                    'countryCode' : data[ 'countryCode' ],
                    'country' : flg,
                    'domain' : data[ 'domain' ]

                }
            pprint( item )
            results.append( item )

    with open( '/home/noname/testhtml/index.html', 'w' ) as f:
        f.write( json2html.convert( json = results, escape=False ) )
        f.write( '\n\n<button onClick="window.location.reload();">Refresh Page</button>')