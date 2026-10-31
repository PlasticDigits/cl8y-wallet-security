#!/usr/bin/env python3
"""Create only this portal's private, nonversioned expiring backup bucket.

S3 SDK credentials are read from the existing platform into operator memory,
never persisted locally or supplied to an application/container. Upload/download uses only the audited operator SDK; native credential-bearing
helpers are never invoked.
"""
import argparse
import datetime
import json
from pathlib import Path
from backup_control import Api, Failure, identifier, s3_client, s3_error_code, safe_main, validate_sealer, write_private


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--source-storage', required=True)
    args = parser.parse_args()
    identifier(args.source_storage)
    config_path = Path(args.config)
    config = json.loads(config_path.read_text())
    api = Api()
    validate_sealer(api, config)
    source = api.call('GET', '/s3-storages/' + args.source_storage)
    if source.get('uuid') != args.source_storage or not source.get('is_usable'):
        raise Failure('source_platform_storage_not_usable')
    client = s3_client(source)
    bucket = 'cl8y-wallet-security-' + identifier(config['portal_app_uuid'])[:12] + '-encrypted'
    if config.get('bucket_name') not in (None, bucket):
        raise Failure('offhost_bucket_identity_changed')
    marker = {'application': 'cl8y-wallet-security', 'portal_app_uuid': config['portal_app_uuid'],
              'sealer_uuid': config['sealer_uuid']}
    exists = True
    try:
        client.head_bucket(Bucket=bucket)
    except Exception as error:
        if s3_error_code(error) not in {'404', 'NoSuchBucket'}:
            raise Failure('offhost_bucket_head_' + s3_error_code(error)) from None
        exists = False
    if not exists:
        # Persist the attempt before its effect; an unknown result is resolved by
        # HEAD/ACL on retry, never blindly repeated or applied to another bucket.
        config.update(bucket_name=bucket, bucket_create_attempted=True)
        write_private(config_path, config)
        try:
            client.create_bucket(Bucket=bucket, ACL='private')
        except Exception as error:
            raise Failure('own_bucket_create_' + s3_error_code(error)) from None
        config['bucket_created_by_this_operator'] = True
        write_private(config_path, config)
    elif not config.get('bucket_created_by_this_operator'):
        # No ownership evidence means no lifecycle/config mutation at all.
        raise Failure('existing_bucket_not_proven_owned')
    acl = client.get_bucket_acl(Bucket=bucket)
    owner = acl.get('Owner', {}).get('ID')
    if not owner or config.get('bucket_owner_id') not in (None, owner):
        raise Failure('offhost_bucket_owner_changed')
    for grant in acl.get('Grants', []):
        if grant.get('Grantee', {}).get('Type') != 'CanonicalUser' or grant.get('Grantee', {}).get('ID') != owner:
            raise Failure('offhost_bucket_not_private')
    config['bucket_owner_id'] = owner
    versioning = client.get_bucket_versioning(Bucket=bucket)
    if versioning.get('Status'):
        raise Failure('own_bucket_must_remain_never_versioned')
    lifecycle = {'Rules': [{'ID': 'wallet-security-four-day-expiry', 'Status': 'Enabled',
                           'Prefix': '', 'Expiration': {'Days': 4},
                           'AbortIncompleteMultipartUpload': {'DaysAfterInitiation': 1}}]}
    client.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=lifecycle)
    actual = client.get_bucket_lifecycle_configuration(Bucket=bucket)
    rules = actual.get('Rules', [])
    if (len(rules) != 1 or rules[0].get('ID') != lifecycle['Rules'][0]['ID']
            or rules[0].get('Status') != 'Enabled' or rules[0].get('Expiration', {}).get('Days') != 4
            or rules[0].get('AbortIncompleteMultipartUpload', {}).get('DaysAfterInitiation') != 1
            or rules[0].get('Prefix', (rules[0].get('Filter') or {}).get('Prefix', '')) != ''):
        raise Failure('offhost_lifecycle_readback_differs')
    # This nonsecret ownership marker may expire; durable identity is also bound
    # to the private operator config and authenticated bucket owner readback.
    client.put_object(Bucket=bucket, Key='.portal-owner.json', Body=json.dumps(marker).encode(),
                      ContentType='application/json', ACL='private')
    config.update(s3_source_uuid=args.source_storage, bucket_name=bucket,
                  offhost_expiration_days=4, lifecycle_verified=True, versioning_enabled=False,
                  lifecycle_checked_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    write_private(config_path, config)
    print(json.dumps({'own_private_bucket_verified': True, 'versioning_enabled': False,
                      'expiration_eligibility_days': 4, 'incomplete_multipart_abort_days': 1,
                      'physical_deletion_timing': 'provider asynchronous; not an exact hard deadline',
                      's3_credentials_in_workload_or_local_files': False, 'native_s3_helpers_invoked': False}))


if __name__ == '__main__':
    safe_main(main)
