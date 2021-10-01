import json,os
import boto3
from datetime import *
import json, logging
import pprint
from elasticsearch import Elasticsearch, helpers, RequestsHttpConnection
import requests
from requests_aws4auth import AWS4Auth
import urllib.parse
from botocore.exceptions import ClientError
from datetime import *
import shlex,subprocess
from urllib.parse import unquote_plus
import elasticsearch


logging.getLogger().setLevel(logging.INFO)
logging.info(f'date={date}')
cfn = boto3.resource('cloudformation')
def lambda_handler(event, context):
    logging.info('lambda_handler starts...')
    s3 = boto3.client('s3')        
    # data = {}
    doc_list=[]
    aws_reg= event['Records'][0]['awsRegion']
    print(aws_reg)
    secret_data_internal = get_secret('nac-es-internal',aws_reg)
    secret_nct_nce_admin = get_secret('nct/nce/os/admin',aws_reg)
    
    role = secret_data_internal['discovery_lambda_role_arn']
    role_data = '{ "backend_roles":["' + role + '"],"hosts": [],"users": ["automation"]}'
    print('role_data',role_data)
    with open("/tmp/"+"/data.json", "w") as write_file:
        write_file.write(role_data)
        
    link=secret_nct_nce_admin['nac_kibana_url']
    link=link[:link.index('_')]
    username=secret_nct_nce_admin['nac_es_admin_user']
    password=secret_nct_nce_admin['nac_es_admin_password']
    data_file_obj = '/tmp/data.json'
    merge_link = '\"https://'+link+'_opendistro/_security/api/rolesmapping/all_access\"'
    cmd = 'curl -X PUT -u \"'+username+':'+password+'\" -H "Content-Type:application/json" ' + merge_link + ' -d \"@/tmp/data.json\"'
    print(cmd)
    status, output = subprocess.getstatusoutput(cmd)
    print(output)

    for record in event['Records']:
        print(record)
        data={}
        data['dest_bucket'] = record['s3']['bucket']['name']
        data['object_key'] = unquote_plus(record['s3']['object']['key'])
        data['size'] = str(record['s3']['object'].get('size', -1))
        data['event_name'] = record['eventName']
        data['event_time'] = record['eventTime']
        data['awsRegion'] = record['awsRegion']
        try:
            data['extension'] = data['object_key'][data['object_key'].index('.') + 1:]
        except:
            data['extension'] = ''
            
        data['volume_name'] = secret_data_internal['volume_name']
        data['root_handle'] = secret_data_internal['root_handle'].replace('.','_').lower()
        data['source_bucket'] = secret_data_internal['discovery_source_bucket']
        print("data['object_key']",data['object_key'])  
        obj1 = s3.get_object(Bucket=data['dest_bucket'], Key=data['object_key'])
        data['content'] = obj1['Body'].read().decode('utf-8')        
        if secret_data_internal['web_access_appliance_address']!='not_found':
            data['access_url']='https://'+secret_data_internal['web_access_appliance_address']+'/fs/view/'+data['object_key']
        else:
            data['access_url']=secret_data_internal['web_access_appliance_address']
        print('data',data)
        print('secret_data_internal',secret_data_internal)
        es_obj = launch_es(secret_nct_nce_admin['nac_es_url'],data['awsRegion'])
        doc_list += [data]
        # connect_es(es_obj,data['root_handle'], data)
        connect_es(es_obj,data['root_handle'], doc_list)

    logging.info('lambda_handler ends...')

def launch_es(es_url,region):

    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)
    es = Elasticsearch(hosts=[{'host': es_url, 'port': 443}], http_auth=awsauth, use_ssl=True, verify_certs=True,
                  connection_class=RequestsHttpConnection)
    return es

def connect_es(es,index, data):
    # print(index)
    update_cnt = 0
    max_id = 0
    try:
        # es.index(index=index, doc_type="_doc", id=1, body=data)
        # print(es.get(index=index, doc_type="_doc", id=1))
        logging.info("\nAttempting to index the list of docs using helpers.bulk()")
        # use the helpers library's Bulk API to index list of Elasticsearch docs
        resp = helpers.bulk(es, data, index=index, doc_type="_doc")
        # print the response returned by Elasticsearch
        print("helpers.bulk() RESPONSE:", resp)
        print("helpers.bulk() RESPONSE:", json.dumps(resp, indent=4))
    except Exception as e:
        logging.error('ERROR: {0}'.format(str(e)))
        logging.error('ERROR: Unable to index line:"{0}"'.format(str(data['object_key'])))
        print(e)
        
def get_secret(secret_name,region_name):

    secret = ''
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name,
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print("The requested secret " + secret_name + " was not found")
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            print("The request was invalid due to:", e)
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            print("The request had invalid params:", e)
        elif e.response['Error']['Code'] == 'DecryptionFailure':
            print("The requested secret can't be decrypted using the provided KMS key:", e)
        elif e.response['Error']['Code'] == 'InternalServiceError':
            print("An error occurred on service side:", e)
    else:
        # Secrets Manager decrypts the secret value using the associated KMS CMK
        # Depending on whether the secret was a string or binary, only one of these fields will be populated
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            #print('text_secret_data',secret)
        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            #print('text_secret_data',secret)
    return json.loads(secret)
