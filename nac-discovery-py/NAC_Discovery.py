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

# region = 'us-east-1'  # For example, us-west-1
# service = 'es'
# credentials = boto3.Session().get_credentials()
# awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)

# host = 'search-es-strikers-iwclhxjxbwgqzpnsvl4iku7nfq.us-east-1.es.amazonaws.com'  # The ES domain endpoint with
# # https:// and a trailing slash index = 'movies' url = host + '/' + index + '/_search'

# es = Elasticsearch(hosts=[{'host': host, 'port': 443}], http_auth=awsauth, use_ssl=True, verify_certs=True,
#                   connection_class=RequestsHttpConnection)
logging.getLogger().setLevel(logging.INFO)
logging.info(f'date={date}')
cfn = boto3.resource('cloudformation')
def lambda_handler(event, context):
    logging.info('lambda_handler starts...')
    s3 = boto3.client('s3')
    data = {}
    aws_reg= event['Records'][0]['awsRegion']
    print(aws_reg)
    secret_data_internal = get_secret('nac-es-internal',aws_reg)
    # secret_data_prod = get_secret(secret_data_internal['user-secret-name'],secret_data_internal['aws-region']) 
    
    role = secret_data_internal['discovery_lambda_role_arn']
    role_data = '{ "backend_roles":["' + role + '"],"hosts": [],"users": ["automation"]}'
    print('role_data',role_data)
    with open("/tmp/"+"/data.json", "w") as write_file:
        write_file.write(role_data)
    link = secret_data_internal['es_url']
    data_file_obj = '/tmp/data.json'
    merge_link = '\"https://'+link+'/_opendistro/_security/api/rolesmapping/all_access\"'
    cmd = 'curl -X PUT -u \"automation:Dangerous@123\" -H "Content-Type:application/json" ' + merge_link + ' -d \"@/tmp/data.json\"'

    status, output = subprocess.getstatusoutput(cmd)
    print(output)

    for record in event['Records']:
        print(record)
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
        es_obj = launch_es(secret_data_internal['es_url'],data['awsRegion'])
 
        connect_es(es_obj,data['root_handle'], data)
        # del_cloudformation_stack(secret_data_internal['nac-stack'])
        #stack_name=secret_data_internal['nac_stack']
        #stack = cfn.Stack(stack_name)
        #stack.delete()
    logging.info('lambda_handler ends...')

def launch_es(es_url,region):
    # region = 'us-east-1'  # For example, us-west-1
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)
    es = Elasticsearch(hosts=[{'host': es_url, 'port': 443}], http_auth=awsauth, use_ssl=True, verify_certs=True,
                  connection_class=RequestsHttpConnection)
    return es

def del_cloudformation_stack(stack_name):
    try:

        print('Inside Del cloudformation')
        print(stack_name)
        # cfn = boto3.resource('cloudformation')
        # stacks = [stack for stack in cfn.stacks.all() if stack.stack_status in statuses]
        print(stack_name)
        print(stacks)
        # cfn = boto3.resource('cloudformation')
        stack = cfn.Stack(stack_name)
        stack.delete()
    except Exception as e:
        logging.error('Error occurred..',e)

def create_index_name(data):
    # dot_index = str(file_name).index('.')
    # slash = str(file_name).index('/')
    # split_files_n_folders = data['object_key'].split('/')
    # file_name = split_files_n_folders[len(split_files_n_folders) - 1]
    # if file_name.isspace():
    #     str(file_name).replace(' ', '_')
    # index = data['nmc_details'] + '_' + data['filer_details'] + '_' + (
    #     data['object_key'].replace('/', '_').replace('.', '_'))
    # # index = (file_name + '_' + str(size) + '_' + str(timing[:19]).replace(':', '_')).replace('.', '_')
    # lower_name_index = index.lower()
    # return lower_name_index
    logging.info('create_index_name')

def connect_es(es,index, data):
    # print(index)
    update_cnt = 0
    max_id = 0
    try:
        # for elem in es.cat.indices(format="json"):
        #     print(index) 
        #     query = {
        #         'query': {
        #             'bool': {
        #                 'must': [
        #                     {'match': {'content': data['content']}},
        #                     {'match': {'object_key': data['object_key']}}
        #                 ]
        #             }
        #         }
        #     }
        #     # query = {
        #     #     'query': {
        #     #         'bool': {
        #     #             'filter': [
        #     #                 {'term': {'content': data['content']}},
        #     #                 {'term': {'object_key': data['object_key']}} 
        #     #             ]
        #     #         }
        #     #     }
        #     # }
        #     resp = es.search(index=elem['index'], body=query)
        #     for i in resp['hits']['hits']:
        #         print(i)
        #         es.index(index=i['_index'], doc_type="_doc", id=i['_id'], body=data)
        #         print(es.get(index=i['_index'], doc_type="_doc", id=i['_id']))
        #         update_cnt += 1
        # if update_cnt == 0: 
        #     if es.indices.exists(index=index):
        #         res = es.count(index=index)
        #         max_id=int(res['count'])
        #         logging.info(max_id)
        #     es.index(index=index, doc_type="_doc", id=max_id + 1, body=data)
        #     print(es.get(index=index, doc_type="_doc", id=max_id + 1))
        es.index(index=index, doc_type="_doc", id=1, body=data)
        print(es.get(index=index, doc_type="_doc", id=1))
    except Exception as e:
        logging.error('ERROR: {0}'.format(str(e)))
        logging.error('ERROR: Unable to index line:"{0}"'.format(str(data['object_key'])))
        print(e)
        
def get_secret(secret_name,region_name):
    # secret_name = "prod/nac"
    # region_name = "us-east-1"
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
        # print('get_secret_value_response',get_secret_value_response)
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
