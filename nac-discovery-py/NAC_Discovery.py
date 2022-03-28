import json,os  
import boto3
from datetime import *
import json, logging
import pprint,re
from elasticsearch import Elasticsearch, helpers
from opensearchpy import OpenSearch,helpers, RequestsHttpConnection
import requests
from requests_aws4auth import AWS4Auth
import urllib.parse
from botocore.exceptions import ClientError
from datetime import *
import shlex,subprocess
from urllib.parse import unquote_plus
import elasticsearch
# import PyPDF2
from io import BytesIO
import io  
from pptx import Presentation
import fitz
from requests.auth import HTTPBasicAuth
from docx import Document
import pandas as pd


logging.getLogger().setLevel(logging.INFO)
logging.info(f'date={date}')
cfn = boto3.resource('cloudformation')
def lambda_handler(event, context):
    logging.info('lambda_handler starts...')
    print("Lambda function ARN:", context.invoked_function_arn)
    runtime_region = os.environ['AWS_REGION'] 
    context_arn=context.invoked_function_arn
    u_id=context_arn.split('-')[-1]
    print('u_id',u_id)
    print('***********************************************')
    s3 = boto3.client('s3')        
    data={}
    doc_list=[]
    check=0
    secret_data_internal = get_secret(
        'nasuni-labs-internal-'+u_id, runtime_region)
    secret_nct_nce_admin = get_secret('nasuni-labs-os-admin',runtime_region) 
    
    role = secret_data_internal['discovery_lambda_role_arn']
    username=secret_nct_nce_admin['nac_es_admin_user']
    role_data = '{"backend_roles":["' +role + '"],"hosts": [],"users": ["'+username+'"]}'
    print('role_data',role_data)
    with open("/tmp/"+"/data.json", "w") as write_file:
        write_file.write(role_data)
        
    link=secret_nct_nce_admin['nac_kibana_url']
    link=link[:link.index('_')]

    password=secret_nct_nce_admin['nac_es_admin_password']
    data_file_obj = '/tmp/data.json'
    merge_link = '\"https://'+link+'_opendistro/_security/api/rolesmapping/all_access\"'
    url = 'https://' + link + '_opendistro/_security/api/rolesmapping/all_access/'

    headers = {'content-type': 'application/json'}
    response = requests.put(url, auth=HTTPBasicAuth(username, password), headers=headers, data=role_data)
    print(response.text)
    
    #Deletion of folder from s3
    
    
    for record in event['Records']:
        print(record)
        data['dest_bucket'] = record['s3']['bucket']['name']
        data['object_key'] = unquote_plus(record['s3']['object']['key'])
        data['size'] = str(record['s3']['object'].get('size', -1))
        file_name=os.path.basename(data['object_key'])
        data['event_name'] = record['eventName']
        data['event_time'] = record['eventTime']
        data['awsRegion'] = record['awsRegion']

        data['extension'] = file_name[file_name.index('.')+1:]
        data['volume_name'] = secret_data_internal['volume_name']
        
        #data['root_handle'] = secret_data_internal['root_handle'].replace('.','_').lower()
        data['root_handle'] = re.sub('[!@#$%^&*()+?=,<>/.]', '-', secret_data_internal['root_handle']).lower()
        data['source_bucket'] = secret_data_internal['discovery_source_bucket']
        print("data['object_key']",data['object_key'])  
        print("data['dest_bucket']",data['dest_bucket'])  
        obj1 = s3.get_object(Bucket=data['dest_bucket'], Key=data['object_key'])
        if data['extension'] in ['csv','txt']:
            data['content'] = obj1['Body'].read().decode('utf-8')
        elif data['extension'] == 'pdf':
            file_content = obj1['Body'].read()
            text = ""
            with fitz.open(stream=file_content, filetype="pdf") as doc:
                
                # iterating through pdf file pages
                for page in doc:
                    # fetching & appending text to text variable of each page
                    text += page.getText()

            print('pdf data priting',text)
            data['content'] = text
        elif data['extension'] in ['docx','doc']:
           fs = obj1['Body'].read()
           sentence = str(parseDocx(fs))
           print('docx data priting',sentence)
           data['content'] = sentence
        elif data['extension'] in ['xlsx','xls']:
            file_content = obj1['Body'].read()
            read_excel_data = io.BytesIO(file_content)
            df = pd.read_excel(read_excel_data) 
            df = df.to_string() 
            print('xlsx data priting',df)
            data['content'] = df 
        elif data['extension'] == 'pptx':
            print('data[extension] elif',data['extension'])
            pptx_content = obj1['Body'].read()
            ppt = Presentation(io.BytesIO(pptx_content))
            pptx_data=''
            for slide in ppt.slides:
                for shape in slide.shapes:
                    if not shape.has_text_frame:
                        continue
                    for paragraph in shape.text_frame.paragraphs:
                        for run in paragraph.runs:
                            pptx_data+=run.text
            print(pptx_data)
            data['content'] = pptx_data
            
            

        if secret_data_internal['web_access_appliance_address']!='not_found':
            data['access_url']='https://'+secret_data_internal['web_access_appliance_address']+'/fs/view/'+data['volume_name']+'/'+file_name
        else:
            data['access_url']=secret_data_internal['web_access_appliance_address']
        print('data',data)
        print('secret_data_internal',secret_data_internal)
        es_obj = launch_es(secret_nct_nce_admin['nac_es_url'],data['awsRegion'])
        
        check=connect_es(es_obj,data['root_handle'], data) 
    #Deletion of folder from s3
    if check == 0:
        print('Insertion into ES success.Hence deleting s3 bucket folder')
        del_s3_folder(data['object_key'],data['dest_bucket'])
    else:
        print('Not deleting the s3 bucket folder all data not got loaded into ES.') 

    logging.info('lambda_handler ends...')
def parseDocx(data):
    data = io.BytesIO(data)
    document = Document(docx = data)
    content = ''
    for para in document.paragraphs:
        data = para.text
        content+= data
    return content

def del_s3_folder(full_path,dest_bucket):
    print("Full Path:-",full_path)
    path=os.path.dirname(full_path)
    print("Folder Path:-",path)
    s3 = boto3.resource('s3') 
    bucket = s3.Bucket(dest_bucket)
    bucket.objects.filter(Prefix=path).delete()
    

def launch_es(es_url,region):

    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region, service, session_token=credentials.token)
    # es = Elasticsearch(hosts=[{'host': es_url, 'port': 443}], http_auth=awsauth, use_ssl=True, verify_certs=True)
    # es = Elasticsearch(hosts=[{'host': es_url, 'port': 443}], http_auth=awsauth, verify_certs=True)
    es = OpenSearch(hosts=[{'host': es_url, 'port': 443}], http_auth=awsauth, use_ssl=True, verify_certs=True,connection_class = RequestsHttpConnection)
    
    return es
    
def connect_es(es,index, data):
    #CTPROJECT-125
    try:
        flag = 0
        for elem in es.cat.indices(format="json"):
            query = {"query": {"match_all": {}}}
            resp = es.search(index=elem['index'], body=query)
            for i in resp['hits']['hits']:
                idx_content = i['_source'].get('content', 0)
                idx_object_key = i['_source'].get('object_key', 0)
                if idx_content == data['content'] and idx_object_key == data['object_key']:
                    flag = 1
                    print("Indexing is doing when the idx_content and idx_object_key has matched", resp)
                    es.index(index=i['_index'], doc_type="_doc", id=i['_id'], body=data)
                    break

        if flag == 0:
            doc_list = []
            doc_list += [data]
            logging.info("\nAttempting to index the list of docs using helpers.bulk()")
            # use the helpers library's Bulk API to index list of Elasticsearch docs
            resp = helpers.bulk(es, doc_list, index=data['root_handle'], doc_type="_doc")
            # print the response returned by Elasticsearch
            print("helpers.bulk() RESPONSE:", resp)
            print("helpers.bulk() RESPONSE:", json.dumps(resp, indent=4))
        return 0
    except Exception as e:
        logging.error('ERROR: {0}'.format(str(e)))
        logging.error('ERROR: Unable to index line:"{0}"'.format(str(data['object_key'])))
        print(e)
        return 1

        
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

        else:
            secret = base64.b64decode(get_secret_value_response['SecretBinary'])

    return json.loads(secret)
