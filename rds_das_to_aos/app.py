#This Lambda function reads the Kinesis Firehose records as Input, decrypt the log records using KMS key, unzip the records and then categories the event type into S3 folder structure. 
from __future__ import print_function
import json
import boto3
import base64
import zlib 
import os
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType
import datetime
import requests
from requests_aws4auth import AWS4Auth
# from opensearchpy.helpers import bulk
# from awswrangler import opensearch



REGION_NAME = os.environ['region_name'] # 'us-east-1'
RESOURCE_ID = os.environ['resource_id'] #'cluster-2VRZBI263EBXMYD3BQUFSIQ554'

enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)
kms = boto3.client('kms', region_name=REGION_NAME)
todays_date = datetime.datetime.now()

# for push es
service = 'es'
credentials = boto3.Session().get_credentials()
awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, REGION_NAME, service, session_token=credentials.token)
host = os.environ['es_url'] #	https://search-opensearch-63ngpkln64v3abzuspbw5dsrkm.us-east-1.es.amazonaws.com
index = os.environ['es_index']
datatype = '_doc'
url = host + '/' + index + '/' + datatype + '/'

headers = { "Content-Type": "application/json" }


class MyRawMasterKeyProvider(RawMasterKeyProvider):
    provider_id = "BC"
    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj
    def __init__(self, plain_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
                                        wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)
    def _get_raw_key(self, key_id):
        return self.wrapping_key

def decrypt_payload(payload, data_key):
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    #Decrypt the records using the master key.
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(master_key_provider=my_key_provider))
    return decrypted_plaintext

def decrypt_decompress(payload, key):
    decrypted = decrypt_payload(payload, key)
    #Decompress the records using zlib library.
    decrypted = zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
    return decrypted

#Lambda Handler entry point
def lambda_handler(event, context):
    output = []
    # print("Received event: " + json.dumps(event, indent=2))
    count = 0
    for dasRecord in event['Records']:
        id = dasRecord['eventID']
        timestamp = dasRecord['kinesis']['approximateArrivalTimestamp']
        
        record_data = dasRecord['kinesis']['data']
        record_data = base64.b64decode(record_data)
        record_data = json.loads(record_data)
        payload_decoded = base64.b64decode(record_data['databaseActivityEvents'])
        data_key_decoded = base64.b64decode(record_data['key'])
        data_key_decrypt_result = kms.decrypt(CiphertextBlob=data_key_decoded,
                                              EncryptionContext={'aws:rds:db-id': RESOURCE_ID})
                                              
        payload = decrypt_decompress(payload_decoded, data_key_decrypt_result['Plaintext'])  
        payload = json.loads(payload)
        
        if payload['type'] == 'DatabaseActivityMonitoringRecord':
            
            documents = []
            for dbEvent in payload['databaseActivityEventList']:
                
                if dbEvent['type']== "heartbeat": #or  eventType == "READ":
                    print ("Heart beat event - ignored event, dropping it.")
                    continue

                # Create the JSON document
                document = { "id": id, "timestamp": timestamp, "message": dbEvent }
                documents.append(document)
                # Index the document
                r = requests.put(url + id, auth=awsauth, json=document, headers=headers)
                print(r.json())
                count += 1
        
        
    print ('Processed ' + str(count) + ' items.')
    return 'Processed ' + str(count) + ' items.'
        
