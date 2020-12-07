#!/usr/bin/env python

import os
import uuid
import sys
import base64
from os.path import dirname, abspath
from datetime import datetime, timedelta
import requests
import json
import re
import argparse
import six.moves.configparser
import logging
from logging.handlers import RotatingFileHandler
from glob import glob

def parse_args():
    parser = argparse.ArgumentParser(description='Download SEPC logs to the local filesystem for LogRhythm consumption.')

    parser.add_argument("-c", "--config-file", help="Path to sepc.conf, defaults to sepc.conf in same directory as this script.",
                        default=os.path.join(sys.path[0], 'sepc.conf'))
    parser.add_argument("-l", "--log-path", help="Path to store the log file in, defaults to the 'logs' directory beneath this script.",
                        default=os.path.join(sys.path[0], 'logs'))
    parser.add_argument("-s", "--state-path", help="Path to store the state file in, defaults to the same directory as the log file.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose mode.")
    return parser.parse_args()

# Main variables
args = parse_args()
config_path = args.config_file
log_path = args.log_path
state_path = args.state_path if args.state_path else args.log_path

proxies = []
# proxies = {
#    "http": "http://10.1.1.55:8080",
#    "https": "https://10.1.1.55:8080"
# }

state_file = os.path.join(state_path,'sepc_state.json')
logging.basicConfig(format='%(message)s', handlers=[RotatingFileHandler(state_file,
                    maxBytes=0.5 * 1024 * 1024, # 0.5mb
                    backupCount=10)])
logger = logging.getLogger("SEPC State Rotate")
logger.setLevel(logging.INFO)

config = six.moves.configparser.ConfigParser()
config.read(config_path)
config_d = dict(config.items('sepc'))

client_id = config_d['client_id']
client_secret = config_d['client_secret']
client_credentials = (client_id + ':' + client_secret).encode('utf-8')
api_base_url = 'api.sep.securitycloud.symantec.com/'

def auth_token(token):
    auth_uri = 'v1/oauth2/tokens'
    url = 'https://' + api_base_url + auth_uri
    b64_credentials = (base64.b64encode(client_credentials)).decode('ascii')
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic %s' % b64_credentials
    }
    if proxies:
        r = requests.post(url=url, headers=headers, proxies=proxies)
    else:
        r = requests.post(url=url, headers=headers)
    data = r.json()
    access_token = data['access_token']
    return access_token

def load_state_from_file(state):
    date = datetime.now()
    try:
    # Using last timestamp from state file as end_date
        with open(state_file,'r') as r:
            if os.path.getsize(state_file) > 0:
                state=(r.readlines()[-1]) + '-00:00'
                state=re.sub('"','',state)
                state=re.sub('\n','',state)
                state=re.sub('Z','',state)
            else:
            #    print('State file is empty or new. Assigning start_date to 30 minutes ago.')
            #    state = (date - timedelta(minutes=30)).isoformat()[:-3] + '-00:00'
               print('State file is empty or new. Assigning start_date to 7 days ago.')
               state = (date - timedelta(days=7)).isoformat()[:-3] + '-00:00'
    except IOError:
        # print('State file is empty or new. Assigning start_date to 30 minutes ago.')
        # state = (date - timedelta(minutes=30)).isoformat()[:-3] + '-00:00'
        print('State file could not be read, assigning start_date to 7 days ago.')
        state = (date - timedelta(days=7)).isoformat()[:-3] + '-00:00'
    return state

def event_return():
    event_uri = 'v1/event-search' 
    url='https://' + api_base_url + event_uri
    access_token=''
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': 'Bearer %s' % auth_token(access_token)
    }
    date = datetime.now()
    end_date = (date.isoformat())[:-3] + '-00:00'
    # End date is current time
    # Using last timestamp from state file as start_date
    start_date = ''
    start_date = load_state_from_file(start_date)
    
    data = {}
    body = { 
        'product': 'SAEP',
        'feature_name': 'ALL',
        'limit': '1000',
        'start_date': start_date,
        'end_date': end_date
    }
    if proxies:
        try:
            result = requests.post(url=url, headers=headers, data=json.dumps(body), proxies=proxies)
            data = result.json() 
        except requests.ConnectionError as e:
            print(e)
    else:
        result = requests.post(url=url, headers=headers, data=json.dumps(body))
        data = result.json()  

    if os.path.exists(state_file):
        last_time = data['events'][-1]['time']
        with open(state_file,'r') as r:
            try:
                start_check=re.sub('\n','',re.sub('"','',(r.readlines()[-1])))
            except IndexError:
                start_check=''
        if (start_check == last_time):
            print('Log file up to date, do not post request for events again')  
            data = {}
        else:
            print('Events found, returning events')
            return data 
    else: 
        return data

# Delete old logs, default to 30 days
def remove_logs(ttl = 30):
    try:
        # Logs deleted count
        deleted_count = 0

        # Get oldest date to keep
        current_date = datetime.now()
        current_datetime = datetime(year=current_date.year, month=current_date.month, day=current_date.day)
        ttl_date = current_datetime - timedelta(days=ttl)

        # Loop through log files
        for log_file_path in glob(os.path.join(log_path, '*.log')):
            # Get date from filename
            log_file_date = datetime.strptime(os.path.basename(log_file_path).replace('.log', ''), '%Y-%m-%d')

            # If log date is older than TTL, remove
            if log_file_date < ttl_date:
                os.remove(log_file_path)
                deleted_count +=1
    except Exception as e:
        raise e
    
    # Return total number of log files deleted
    return deleted_count

def main():
    data_json = {}
    data_json = event_return()
    if data_json == None:
        print ('No events to return')
        print("Log files removed from cleanup: "+str(remove_logs()))
        exit(0)
    elif not 'events' in data_json or len(data_json['events']) == 0:
        print ('No events to return')
        print("Log files removed from cleanup: "+str(remove_logs()))
        exit(0)
    else:
        # Append events from json to log file
        for j in data_json['events']:
            data_time = json.dumps(j['time']) # String dump key value to manipulate
            data_time = data_time.strip('"') # Turning "2019-12-14T07:46:41.089Z" into 2019-12-14T07:46:41 for LR to parse
            data_time = data_time[:-5] # <yy>-<M>-<d>T<h>:<m>:<s>
            # Log file name based on event date
            try:
                log_file = os.path.join(log_path, data_time[0:10]+'.log')
                with open(log_file, 'a') as log:
                    events = json.dumps(j)
                    log.write(data_time + ' ' + events + '\n')
                    print('Writing events to log file')
            except IOError:
                print("Unable to write to " + log_file + ", exiting.")
                sys.exit(1)
            # Writing timestamps of all events to file for the purpose of measuring state
            try:
                logger.info(j['time'])
            except IOError:
                print("Unable to write to " + state_file + ", exiting.")
                sys.exit(1)

    while data_json != None:
        print ('Recursively calling main function to keep searching for events')
        main()
main()