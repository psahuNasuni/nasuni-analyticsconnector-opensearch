import pprint
import shlex
import urllib.parse, json, subprocess
import urllib.request as urlrq
import ssl, os, logging
import sys
from datetime import *


if len(sys.argv) < 6:
    print('Usage -- python fetch_nmc_api_23-8.py <ip_address> <username> <password> <volume_name> <rid>')
    exit()

logging.getLogger().setLevel(logging.INFO)
logging.info(f'date={date}')

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    ssl._create_default_https_context = ssl._create_unverified_context

try:
    file_name,endpoint, username, password, volume_name, rid = sys.argv
    logging.info(sys.argv)
    url = 'https://' + endpoint + '/auth/login/'
    logging.info(url)
    values = {'username': username, 'password': password}
    data = urllib.parse.urlencode(values).encode("utf-8")
    logging.info(data)
    response = urllib.request.urlopen(url, data, timeout=5)
    logging.info(response)
    result = json.loads(response.read().decode('utf-8'))
    logging.info(result)

    cmd = 'curl -k -X GET -H \"Accept: application/json\" -H \"Authorization: Token ' + result[
        'token'] + '\" \"https://' + endpoint + '/volumes/\"'
    args = shlex.split(cmd)
    process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    json_data = json.loads(stdout.decode('utf-8'))
    # pprint.pprint(json.loads(stdout.decode('utf-8')))
    for i in json_data['items']:
        if i['name'] == volume_name:
            # dictionary = {
            #     "root_handle": i['root_handle'],
            #     "source_bucket": i['bucket'],
            #     "volume_guid": i['guid']
            # }
            # person_json = json.dumps(dictionary)
            # print(person_json)
            toc_file = open('nmc_api_data_root_handle_' + rid + '.txt', 'w')
            toc_file.write(i['root_handle'])
            # print('toc_handle',i['root_handle'])
            src_bucket = open('nmc_api_data_source_bucket_' + rid + '.txt', 'w')
            src_bucket.write(i['bucket'])
            # print('source_bucket', i['bucket'])
            v_guid = open('nmc_api_data_v_guid_' + rid + '.txt', 'w')
            v_guid.write(i['guid'])
            # print('volume_guid', i['guid'])
            # external_share_url = open('nmc_api_data_external_share_url_' + rid + '.txt', 'w')
            # external_share_url.write('external_share_url 1')
            # external_share_volume_name = open('nmc_api_data_external_share_volume_name_' + rid + '.txt', 'w')
            # external_share_volume_name.write('external_share_volume_name 1')
            
except Exception as e:
    print('Runtime Errors', e)
