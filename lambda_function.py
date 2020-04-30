"""Certificate Delegation"""
import os
import logging
import time
import boto3
from crhelper import CfnResource

logger = logging.getLogger()
helper = CfnResource(
    json_logging=False, log_level='DEBUG',
    boto_level='CRITICAL'
)

RP = 'ResourceProperties'
WA = 'WaitAttempt'
CA = 'CertArn'
RR = 'ResourceRecord'
HZS = 'HostedZones'
CAF = 'CertificateArn'
C = 'Certificate'
DVO = 'DomainValidationOptions'
CHD = 'CrHelperData'


@helper.create
def create(event, context):
    """Create"""
    logger.info('Got Create')
    properties = event.get(RP, {})
    naked_domain_name = properties.get('DomainName', None)
    wilcarded_domain = '*.' + naked_domain_name

    acm_client = boto3.client('acm', region_name=os.getenv('ACM_CERT_REGION'))
    response = acm_client.request_certificate(
        DomainName=naked_domain_name,
        ValidationMethod='DNS',
        SubjectAlternativeNames=[wilcarded_domain],
        Options={'CertificateTransparencyLoggingPreference': 'ENABLED'}
    )

    cert_arn = response.get(CAF)
    logger.info('CertArn: %s', cert_arn)

    cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
    validation_options = next(iter(cert_details.get(C, {}).get(DVO, [])), {})
    while RR not in validation_options:
        cert_details = acm_client.describe_certificate(CertificateArn=cert_arn)
        validation_options = next(iter(cert_details.get(C, {}).get(DVO, [])), {})
        time.sleep(10)

    # Add tags to cert
    acm_client.add_tags_to_certificate(
        CertificateArn=cert_arn,
        Tags=[
            {'Key': 'Name', 'Value': os.getenv('NAME_CERT_TAG')},
            {'Key': 'Application', 'Value': os.getenv('APPLICATION_CERT_TAG')},
            {'Key': 'Environment', 'Value': os.getenv('ENVIRONMENT_CERT_TAG')}
        ]
    )

    validation_record_details = validation_options.get(RR)
    logging.info('MakeDNS: %s', validation_record_details)

    r53_client = boto3.client(
        'route53', region_name=os.getenv('AWS_DEFAULT_REGION'))

    hosted_zones = r53_client.list_hosted_zones_by_name(
        DNSName=naked_domain_name)

    if not hosted_zones[HZS] or hosted_zones[HZS][0]['Name'] != naked_domain_name + '.':
        raise RuntimeError(
            'Need at least 1 HZ with name : {}'.format(naked_domain_name))

    hosted_zone_id = hosted_zones[HZS][0]['Id']

    r53_client.change_resource_record_sets(
        HostedZoneId=hosted_zone_id,
        ChangeBatch={
            'Changes': [
                {
                    'Action': 'UPSERT',
                    'ResourceRecordSet': {
                        'Name': validation_record_details.get('Name'),
                        'Type': validation_record_details.get('Type'),
                        'TTL': 300,
                        'ResourceRecords': [
                            {'Value': validation_record_details.get('Value')}
                        ]
                    }
                }
            ]
        }
    )

    helper.Data.update({'Arn': cert_arn})

# Need this stub function to prevent errors
@helper.update
def update(event, context):
    """Update"""
    logger.info('Got Update')
    return event.get('PhysicalResourceId', None)

# Need this stub function to prevent errors
@helper.delete
def delete(event, context):
    """Delete"""
    logger.info('Got Delete')


@helper.poll_create
def poll_create(event, context):
    """Poll Create"""
    logger.info('Got create poll')
    # Return a resource id or True to indicate that creation is complete.
    # If True is returned an id will be generated
    cert_arn = event[CHD]['Arn']
    acm_client = boto3.client('acm', region_name=os.getenv('ACM_CERT_REGION'))

    logger.info('Checking for validation.')
    resp = acm_client.list_certificates(CertificateStatuses=['ISSUED'])
    if any(cert[CAF] == cert_arn for cert in resp['CertificateSummaryList']):
        logger.info('cert issued')
        return True

    logger.info('Cert not issued yet')
    return False


def lambda_handler(event, context):
    """Default Handler"""
    helper(event, context)
