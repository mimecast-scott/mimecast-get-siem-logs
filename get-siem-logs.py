#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging.handlers
import json
import os
import requests
import base64
import uuid
import datetime
import hashlib
import shutil
import hmac
import time
from zipfile import ZipFile
import io
import sched, time

#try:
APP_ID = os.environ['APP_ID']
#print("APP_ID:" + APP_ID)
APP_KEY = os.environ['APP_KEY']
#print("APP_KEY:" + APP_KEY)
EMAIL_ADDRESS = os.environ['EMAIL_ADDRESS']
#print("EMAIL_ADDRESS:" + EMAIL_ADDRESS)
ACCESS_KEY = os.environ['ACCESS_KEY']
#print("ACCESS_KEY:" + ACCESS_KEY)
SECRET_KEY = os.environ['SECRET_KEY']
#print(" SECRET_KEY:" + SECRET_KEY)
syslog_output = os.environ['SYSLOG_OUTPUT']
#print("SYSLOG_OUTPUT:" + syslog_output)    
syslog_server = os.environ['SYSLOG_SERVER']
#print("SYSLOG_SERVER:" + syslog_server)  
syslog_port = os.environ['SYSLOG_PORT']
#print("SYSLOG_PORT:" + syslog_port)  
delete_files = os.environ['DELETE_FILES']
#print("DELETE_FILES:" + delete_files)  
log_file_threshold = os.environ['LOG_FILE_THRESHOLD']
SCHEDULE_DELAY = int(os.environ['SCHEDULE_DELAY'])
#print(os.environ)

# Set up variables
URI = "/api/audit/get-siem-logs"
LOG_FILE_PATH = "logs"
CHK_POINT_DIR = "chk"
 

# Set up logging (in this case to terminal)
log = logging.getLogger(__name__)
log.root.setLevel(logging.DEBUG)
log_formatter = logging.Formatter('%(levelname)s %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)
 
# Set up syslog output
syslog_handler = logging.handlers.SysLogHandler(address=(syslog_server, syslog_port))
syslog_formatter = logging.Formatter('%(message)s')
syslog_handler.setFormatter(syslog_formatter)
syslogger = logging.getLogger(__name__)
syslogger = logging.getLogger('SysLogger')
syslogger.addHandler(syslog_handler)
 
 
# Supporting methods
def get_hdr_date():
    return datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")
 
 
def read_file(file_name):
    try:
        with open(file_name, 'r') as f:
            data = f.read()
 
        return data
    except Exception as e:
        log.error('Error reading file ' + file_name + '. Cannot continue. Exception: ' + str(e))
        quit()
 
 
def write_file(file_name, data_to_write):
    if '.zip' in file_name:
        try:
            byte_content = io.BytesIO(data_to_write)
            zip_file = ZipFile(byte_content)
            zip_file.extractall(LOG_FILE_PATH)
        except Exception as e:
            log.error('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))
            quit()
 
    else:
        try:
            with open(file_name, 'w') as f:
                f.write(data_to_write)
        except Exception as e:
            log.error('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))
            quit()
 
 
def get_base_url(email_address):
    # Create post body for request
    post_body = dict()
    post_body['data'] = [{}]
    post_body['data'][0]['emailAddress'] = email_address
 
    # Create variables required for request headers
    request_id = str(uuid.uuid4())
    request_date = get_hdr_date()
    headers = {'x-mc-app-id': APP_ID, 'x-mc-req-id': request_id, 'x-mc-date': request_date}
 
    # Send request to API
    log.debug('Sending request to https://api.mimecast.com/api/discover-authentication with request Id: ' +
                  request_id)
    try:
        r = requests.post(url='https://api.mimecast.com/api/login/discover-authentication',
                          data=json.dumps(post_body), headers=headers)
        # Handle Rate Limiting
        if r.status_code == 429:
            log.warning('Rate limit hit. sleeping for ' + str(r.headers['X-RateLimit-Reset'] * 1000))
            time.sleep(r.headers['X-RateLimit-Reset'] * 1000)
    except Exception as e:
        log.error('Unexpected error getting base url. Cannot continue.' + str(e))
        quit()
 
    # Handle error from API
    if r.status_code != 200:
        log.error('Request returned with status code: ' + str(r.status_code) + ', response body: ' +
                      r.text + '. Cannot continue.')
        quit()
 
    # Load response body as JSON
    resp_data = json.loads(r.text)
 
    # Look for api key in region region object to get base url
    if 'region' in resp_data["data"][0]:
        base_url = resp_data["data"][0]["region"]["api"].split('//')
        base_url = base_url[1]
    else:
        # Handle no region found, likely the email address was entered incorrectly
        log.error(
            'No region information returned from API, please check the email address.'
            'Cannot continue')
        quit()
 
    return base_url
 
 
def post_request(base_url, uri, post_body, access_key, secret_key):
 
    # Create variables required for request headers
    request_id = str(uuid.uuid4())
    request_date = get_hdr_date()
 
    unsigned_auth_header = '{date}:{req_id}:{uri}:{app_key}'.format(
        date=request_date,
        req_id=request_id,
        uri=uri,
        app_key=APP_KEY
    )
    hmac_sha1 = hmac.new(
        base64.b64decode(secret_key),
        unsigned_auth_header.encode(),
        digestmod=hashlib.sha1).digest()
    sig = base64.encodebytes(hmac_sha1).rstrip()
    headers = {
        'Authorization': 'MC ' + access_key + ':' + sig.decode(),
        'x-mc-app-id': APP_ID,
        'x-mc-date': request_date,
        'x-mc-req-id': request_id,
        'Content-Type': 'application/json'
    }
 
    try:
        # Send request to API
        log.debug('Sending request to https://' + base_url + uri + ' with request Id: ' + request_id)
        r = requests.post(url='https://' + base_url + uri, data=json.dumps(post_body), headers=headers)
 
        # Handle Rate Limiting
        if r.status_code == 429:
            log.warning('Rate limit hit. sleeping for ' + str(r.headers['X-RateLimit-Reset'] * 1000))
            time.sleep(r.headers['X-RateLimit-Reset'] * 1000)
            r = requests.post(url='https://' + base_url + uri, data=json.dumps(post_body), headers=headers)
 
    # Handle errors
    except Exception as e:
        log.error('Unexpected error connecting to API. Exception: ' + str(e))
        return 'error'
    # Handle errors from API
    if r.status_code != 200:
        log.error('Request to ' + uri + ' with , request id: ' + request_id + ' returned with status code: ' +
                      str(r.status_code) + ', response body: ' + r.text)
        return 'error'
 
    # Return response body and response headers
    return r.content, r.headers
 
 
def get_mta_siem_logs(checkpoint_dir, base_url, access_key, secret_key):
    uri = "/api/audit/get-siem-logs"
 
    # Set checkpoint file name to store page token
    checkpoint_filename = os.path.join(checkpoint_dir, 'get_mta_siem_logs_checkpoint')
 
    # Build post body for request
    post_body = dict()
    post_body['data'] = [{}]
    post_body['data'][0]['type'] = 'MTA'
    post_body['data'][0]['compress'] = True
    if os.path.exists(checkpoint_filename):
        post_body['data'][0]['token'] = read_file(checkpoint_filename)
 
    # Send request to API
    resp = post_request(base_url, uri, post_body, access_key, secret_key)
    now = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y")
 
    # Process response
    if resp != 'error':
        resp_body = resp[0]
        resp_headers = resp[1]
        content_type = resp_headers['Content-Type']
 
        # End if response is JSON as there is no log file to download
        if content_type == 'application/json':
            log.info('No more logs available')
            return False
        # Process log file
        elif content_type == 'application/octet-stream':
            file_name = resp_headers['Content-Disposition'].split('=\"')
            file_name = file_name[1][:-1]
 
            # Save files to LOG_FILE_PATH
            write_file(os.path.join(LOG_FILE_PATH, file_name), resp_body)
            # Save mc-siem-token page token to check point directory
            write_file(checkpoint_filename, resp_headers['mc-siem-token'])
 
            try:
                if syslog_output is True:
                    for filename in os.listdir(LOG_FILE_PATH):
                        file_creation_time = time.ctime(os.path.getctime(LOG_FILE_PATH + "/" + filename))
                        if now < file_creation_time or now == file_creation_time:
                            log.info('Loading file: ' + filename + ' to output to ' + syslog_server + ':' + str(syslog_port))
                            with open(file=os.path.join(LOG_FILE_PATH, filename), mode='r', encoding='utf-8') as log_file:
                                lines = log_file.read().splitlines()
                                for line in lines:
                                    syslogger.info(line)
                            log.info('Syslog output completed for file ' + filename)
            except Exception as e:
                log.error('Unexpected error writing to syslog. Exception: ' + str(e))
            # return true to continue loop
            return True
        else:
            # Handle errors
            log.error('Unexpected response')
            for header in resp_headers:
                log.error(header)
            return False
 
 
def run_script(sc):

    # discover base URL
        try:
            base_url = get_base_url(email_address=EMAIL_ADDRESS)
        except Exception as e:
            log.error('Error discovering base url for ' + EMAIL_ADDRESS + ' . Exception: ' + str(e))
            quit()
    
        # Request log data in a loop until there are no more logs to collect
        try:
            log.info('Getting MTA log data')
            while get_mta_siem_logs(checkpoint_dir=CHK_POINT_DIR, base_url=base_url, access_key=ACCESS_KEY,
                                    secret_key=SECRET_KEY) is True:
                log.info('Getting more MTA log files')
        except Exception as e:
            log.error('Unexpected error getting MTA logs ' + (str(e)))
        file_number = len([name for name in os.listdir(LOG_FILE_PATH) if os.path.isfile(name)])
        if delete_files or file_number >= log_file_threshold:
            for filename in os.listdir(LOG_FILE_PATH):
                file_path = os.path.join(LOG_FILE_PATH, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    print('Failed to delete %s. Reason: %s' % (file_path, e))
        #quit()
        print("INFO Script will start again in " + str(SCHEDULE_DELAY) + " seconds.")
        sc.enter(SCHEDULE_DELAY, 1, run_script, (sc,))

        

# Run script
s = sched.scheduler(time.time, time.sleep)
s.enter(SCHEDULE_DELAY, 1, run_script, (s,))
s.run()

