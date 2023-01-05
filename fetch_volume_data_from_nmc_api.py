import pprint
import shlex
import urllib.parse, json, subprocess
import urllib.request as urlrq
import ssl, os
import sys,logging
from datetime import *
import boto3
import requests

if len(sys.argv) < 7:
    print(
        'Usage -- python3 fetch_nmc_api_23-8.py <ip_address> <username> <password> <volume_name> <rid> <web_access_appliance_address>')
    exit()

logging.getLogger().setLevel(logging.INFO)
logging.info(f'date={date}')

if not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None):
    ssl._create_default_https_context = ssl._create_unverified_context

file_name, endpoint, username, password, volume_name, rid, web_access_appliance_address = sys.argv
try:
    session = boto3.Session(profile_name="nasuni")
    credentials = session.get_credentials()

    credentials = credentials.get_frozen_credentials()
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    access_key_file = open('Zaccess_' + rid + '.txt', 'w')
    access_key_file.write(access_key)

    secret_key_file = open('Zsecret_' + rid + '.txt', 'w')
    secret_key_file.write(secret_key)
    access_key_file.close()
    secret_key_file.close()

except Exception as e:
    print('Runtime error while extracting aws keys')

try:
    #file_name, endpoint, username, password, volume_name, rid, web_access_appliance_address = sys.argv
    logging.info(sys.argv)
    url = 'https://' + endpoint + '/api/v1.1/auth/login/'
    logging.info(url)
    values = {'username': username, 'password': password}
    data = urllib.parse.urlencode(values).encode("utf-8")
    logging.info(data)
    response = urllib.request.urlopen(url, data, timeout=5)
    logging.info(response)
    result = json.loads(response.read().decode('utf-8'))
    logging.info(result)

    cmd = 'curl -k -X GET -H \"Accept: application/json\" -H \"Authorization: Token ' + result[
        'token'] + '\" \"https://' + endpoint + '/api/v1.1/volumes/\"'
    logging.info(cmd)
    args = shlex.split(cmd)
    process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    json_data = json.loads(stdout.decode('utf-8'))
    vv_guid = ''
    for i in json_data['items']:
        if i['name'] == volume_name:
            print(i)
            toc_file = open('nmc_api_data_root_handle_' + rid + '.txt', 'w')
            toc_file.write(i['root_handle'])
            # print('toc_handle',i['root_handle'])
            src_bucket = open('nmc_api_data_source_bucket_' + rid + '.txt', 'w')
            src_bucket.write(i['bucket'])
            # print('source_bucket', i['bucket'])
            v_guid = open('nmc_api_data_v_guid_' + rid + '.txt', 'w')
            v_guid.write(i['guid'])
            vv_guid = i['guid']
    # cmd = 'curl -k -X GET -H \"Accept: application/json\" -H \"Authorization: Token ' + result[
    #     'token'] + '\" \"https://' + endpoint + '/api/v1.1/volumes/filers/shares/\"'
    # logging.info(cmd)
    # args = shlex.split(cmd)
    # process = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # stdout, stderr = process.communicate()
    # json_data = json.loads(stdout.decode('utf-8'))
    # My Accelerate Test
    share_url = open('nmc_api_data_external_share_url_' + rid + '.txt', 'w')
    share_url.write(web_access_appliance_address)
    # share_name = open('nmc_api_data_v_share_name_' + rid + '.txt', 'w')
    # share_name.write('-')
    # share_path = open('nmc_api_data_v_share_path_' + rid + '.txt', 'w')
    # share_path.write('-')
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Token {}'.format(result['token'])
    }
    try:
        r = requests.get('https://' + endpoint + '/api/v1.1/volumes/filers/shares/', headers = headers,verify=False)
    except requests.exceptions.RequestException as err:
        logging.error ("OOps: Something Else {}".format(err))
    except requests.exceptions.HTTPError as errh:
        logging.error ("Http Error: {}".format(errh))
    except requests.exceptions.ConnectionError as errc:
        logging.error ("Error Connecting: {}".format(errc))
    except requests.exceptions.Timeout as errt:
        logging.error ("Timeout Error: {}".format(errt))
    except Exception as e:
        logging.error('ERROR: {0}'.format(str(e)))
    
    share_data={}
    name=[]
    path=[]
    for i in r.json()['items']:
        if i['volume_guid'] == vv_guid and i['path']!='\\' and i['browser_access']==True:
            name.append(r""+i['name'].replace('\\','/'))
            path.append(r""+i['path'].replace('\\','/'))
            

    share_data['name']=name
    share_data['path']=path

    logging.info(share_data)
    bucket_name='nasuni-share-data-bucket-storage'
    
    # Create an S3 client
    session = boto3.Session(profile_name='nasuni')
    s3 = session.client('s3')
    # Get the default region for the AWS profile
    default_region = session.region_name

    # Print the default region
    print(default_region)

    # List all of the S3 buckets in your account
    buckets = s3.list_buckets()

    # Check if a bucket with the given name exists
    bucket_exists=0
    if bucket_name in [bucket['Name'] for bucket in buckets['Buckets']]:
        print('Bucket already exists')
        # List all of the objects in the S3 bucket
        response = s3.list_objects(Bucket=bucket_name)


    else:
        print('Bucket does not exist')
        s3.create_bucket(Bucket=bucket_name,CreateBucketConfiguration={'LocationConstraint':default_region})

    if len(share_data['name'])==0 or len(share_data['path']) == 0:
        logging.info('dict is empty'.format(share_data))
        share_name = open('nmc_api_data_v_share_name_' + rid + '.txt', 'w')
        share_name.write('-')
        share_path = open('nmc_api_data_v_share_path_' + rid + '.txt', 'w')
        share_path.write('-')
        share_name.close()
        share_path.close()
        s3.upload_file('nmc_api_data_v_share_name_' + rid + '.txt', bucket_name, 'nmc_api_data_'+rid+'/nmc_api_data_v_share_name_' + rid + '.txt')
        s3.upload_file('nmc_api_data_v_share_path_' + rid + '.txt', bucket_name, 'nmc_api_data_'+rid+'/nmc_api_data_v_share_path_' + rid + '.txt')
    else:
        logging.info('dict has data'.format(share_data))
        share_name = open('nmc_api_data_v_share_name_' + rid + '.txt', 'w')
        share_name.write(str((','.join(share_data['name']))))
        share_path = open('nmc_api_data_v_share_path_' + rid + '.txt', 'w')
        share_path.write(str((','.join(share_data['path']))))
        share_name.close()
        share_path.close()
        s3.upload_file('nmc_api_data_v_share_name_' + rid + '.txt', bucket_name, 'nmc_api_data_'+rid+'/nmc_api_data_v_share_name_' + rid + '.txt')
        s3.upload_file('nmc_api_data_v_share_path_' + rid + '.txt', bucket_name, 'nmc_api_data_'+rid+'/nmc_api_data_v_share_path_' + rid + '.txt')



    # for i in json_data['items']:
    #     if i['volume_guid'] == vv_guid and i['browser_access_settings']['external_share_url'] == web_access_appliance_address:
    #         print(i)
    #         share_url = open('nmc_api_data_external_share_url_' + rid + '.txt', 'w')
    #         share_url.write(i['browser_access_settings']['external_share_url'])
    #     else:
    #         share_url = open('nmc_api_data_external_share_url_' + rid + '.txt', 'w')
    #         share_url.write('not_found')

except Exception as e:
    print('Runtime Errors', e)