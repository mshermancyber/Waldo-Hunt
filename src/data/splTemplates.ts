// ═══════════════════════════════════
// SPL TEMPLATES — AWS
// ═══════════════════════════════════

export const AWS_SPL: Record<string, () => string> = {
  delete_data: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DeleteObject","DeleteObjects","DeleteBucket",
                  "DeleteItem","DeleteTable")
| stats count as delete_count
    dc(requestParameters.bucketName) as bucket_count
    values(requestParameters.bucketName) as buckets
    min(_time) as firstTime max(_time) as lastTime
    by userIdentity.arn awsRegion
| where delete_count > 100
| eval risk_score=case(
    delete_count > 1000, "CRITICAL",
    delete_count > 500,  "HIGH",
    delete_count > 100,  "MEDIUM",
    true(),              "LOW")
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime) ctime(lastTime)
| table userIdentity.arn awsRegion delete_count bucket_count buckets risk_score firstTime lastTime`,

  resource_destroy: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("TerminateInstances","DeleteFunction","DeleteVpc",
                  "DeleteSubnet","DeleteSecurityGroup","DeleteStack",
                  "DeleteCluster","DeleteDBInstance","DeleteDomain")
| stats count as destroy_count
    values(eventName) as actions_taken
    dc(eventName) as unique_action_types
    min(_time) as firstTime
    by userIdentity.arn awsRegion
| where destroy_count > 5 AND unique_action_types >= 2
| eval severity=case(
    destroy_count > 20, "HIGH",
    destroy_count > 10, "MEDIUM",
    true(),             "LOW")
| convert timeformat="%Y-%m-%d %H:%M:%S" ctime(firstTime)
| table userIdentity.arn awsRegion destroy_count unique_action_types actions_taken severity firstTime`,

  config_tamper: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("StopLogging","DeleteTrail","UpdateTrail",
                  "PutBucketPolicy","DeleteBucketPolicy",
                  "AuthorizeSecurityGroupIngress","RevokeSecurityGroupEgress",
                  "DisableEbsEncryptionByDefault","ModifyInstanceAttribute")
| eval tamper_category=case(
    like(eventName,"%Trail%"),    "CloudTrail Tampering",
    like(eventName,"%Bucket%"),   "S3 Policy Change",
    like(eventName,"%Security%"), "Network Control Change",
    true(),                       "Config Change")
| stats count values(eventName) as events
    values(tamper_category) as categories
    by userIdentity.arn sourceIPAddress
| where count > 2 OR like(mvjoin(categories," "),"CloudTrail%")
| table userIdentity.arn sourceIPAddress events categories count`,

  logic_bomb: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutRule","CreateRule","PutTargets",
                  "CreateSchedule","CreateFunction","UpdateFunctionCode")
| rex field=requestParameters "(?i)rate\\((?<schedule_rate>[^)]+)\\)|cron\\((?<cron_expr>[^)]+)\\)"
| eval has_schedule=if(isnotnull(schedule_rate) OR isnotnull(cron_expr),1,0)
| where has_schedule=1
| stats count values(eventName) as events
    values(schedule_rate) as rates
    values(cron_expr) as crons
    by userIdentity.arn requestParameters.name
| table userIdentity.arn requestParameters.name events rates crons count`,

  backup_destroy: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DeleteSnapshot","DeleteDBSnapshot","DeleteDBClusterSnapshot",
                  "DeleteBackup","DeleteRecoveryPoint","DeleteVault")
| stats count as snapshot_deletes
    values(eventName) as delete_types
    dc(requestParameters.snapshotId) as unique_snapshots
    by userIdentity.arn awsRegion
| where snapshot_deletes >= 3
| eval risk=case(
    snapshot_deletes >= 20, "CRITICAL",
    snapshot_deletes >= 10, "HIGH",
    true(),                 "MEDIUM")
| table userIdentity.arn awsRegion snapshot_deletes unique_snapshots delete_types risk`,

  access_revoke: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DeleteUser","DeleteRole","DeleteAccessKey",
                  "DetachUserPolicy","DetachRolePolicy",
                  "RemoveUserFromGroup","DeleteLoginProfile")
| stats count as revoke_count
    dc(requestParameters.userName) as users_affected
    values(eventName) as actions
    by userIdentity.arn
| where revoke_count >= 3
| eval severity=if(users_affected > 5,"HIGH","MEDIUM")
| table userIdentity.arn revoke_count users_affected actions severity`,

  s3_exfil: () => `index=aws_s3_accesslogs sourcetype=aws:s3:accesslogs
    operation IN ("REST.GET.OBJECT","REST.COPY.OBJECT_GET","REST.HEAD.OBJECT")
| stats count as download_count
    sum(bytessent) as total_bytes
    dc(key) as unique_files
    dc(bucket) as bucket_count
    values(bucket) as buckets
    by requester
| where download_count > 200 OR total_bytes > 1073741824
| eval total_gb=round(total_bytes/1073741824,2)
| eval risk=case(
    total_gb > 10,          "CRITICAL",
    download_count > 1000,  "HIGH",
    download_count > 200,   "MEDIUM",
    true(),                 "LOW")
| table requester download_count unique_files total_gb bucket_count buckets risk`,

  repo_clone: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventSource="codecommit.amazonaws.com"
    eventName IN ("GitPull","GitClone","GetRepository","BatchGetRepositories")
| stats count as pull_count
    dc(requestParameters.repositoryName) as repos_accessed
    values(requestParameters.repositoryName) as repo_names
    by userIdentity.arn sourceIPAddress
| where repos_accessed >= 3 OR pull_count > 20
| eval flag=if(repos_accessed > 5,"Mass Clone","Repeated Pull")
| table userIdentity.arn sourceIPAddress pull_count repos_accessed repo_names flag`,

  secrets_access: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventSource IN ("secretsmanager.amazonaws.com","ssm.amazonaws.com")
    eventName IN ("GetSecretValue","DescribeSecret",
                  "GetParameter","GetParameters","GetParametersByPath")
| stats count as access_count
    dc(requestParameters.secretId) as unique_secrets
    values(requestParameters.secretId) as secrets_accessed
    by userIdentity.arn sourceIPAddress
| where access_count > 10 OR unique_secrets > 3
| eval risk=case(
    unique_secrets > 10, "CRITICAL",
    unique_secrets > 5,  "HIGH",
    access_count > 10,   "MEDIUM",
    true(),              "LOW")
| table userIdentity.arn sourceIPAddress access_count unique_secrets secrets_accessed risk`,

  data_stage: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CopyObject","CreateMultipartUpload","PutObject")
| rex field=requestParameters "\"bucketName\":\"(?<dest_bucket>[^\"]+)\""
| rex field=requestParameters "\"copySource\":\"/(?<src_bucket>[^/]+)"
| where isnotnull(src_bucket) AND src_bucket!=dest_bucket
| lookup internal_buckets bucket AS dest_bucket OUTPUT is_internal
| where is_internal!="true" OR isnull(is_internal)
| stats count dc(src_bucket) as src_count
    values(src_bucket) as sources
    values(dest_bucket) as destinations
    by userIdentity.arn
| where count > 10
| table userIdentity.arn count src_count sources destinations`,

  cross_account: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName="AssumeRole"
| rex field=requestParameters "\"roleArn\":\"arn:aws:iam::(?<target_account>\\d{12})"
| where target_account!=aws_account_id
| stats count dc(target_account) as unique_accounts
    values(target_account) as accounts_accessed
    values(requestParameters.roleArn) as roles_assumed
    by userIdentity.arn sourceIPAddress
| where unique_accounts >= 2 OR count > 10
| eval risk=case(
    unique_accounts > 5, "CRITICAL",
    unique_accounts > 2, "HIGH",
    true(),              "MEDIUM")
| table userIdentity.arn sourceIPAddress count unique_accounts accounts_accessed roles_assumed risk`,

  usb_exfil: () => `| comment "USB exfiltration has no direct AWS analog. Use On-Prem EDR/DLP SPL block for this activity."`,

  priv_escalation: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("AttachUserPolicy","AttachRolePolicy","PutUserPolicy","PutRolePolicy",
                  "CreateAccessKey","AddUserToGroup","UpdateAssumeRolePolicy",
                  "CreateRole","CreateUser")
| eval is_admin=if(
    like(requestParameters.policyArn,"%AdministratorAccess%") OR
    like(requestParameters.policyDocument,"%\\*%"),1,0)
| stats count dc(eventName) as action_types
    sum(is_admin) as admin_grants
    values(eventName) as actions
    by userIdentity.arn requestParameters.userName
| where count >= 2 OR admin_grants >= 1
| eval severity=case(
    admin_grants >= 1, "CRITICAL",
    count >= 5,        "HIGH",
    true(),            "MEDIUM")
| table userIdentity.arn requestParameters.userName count admin_grants actions severity`,

  resource_abuse: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("RunInstances","CreateDBInstance","CreateCluster",
                  "RequestSpotFleet","CreateCapacityReservation")
| rex field=requestParameters "\"instanceType\":\"(?<instance_type>[^\"]+)\""
| eval is_large=if(match(instance_type,"(p3|p4|g4|g5|x1|x2|u-|metal|48xl|96xl)"),1,0)
| stats count dc(awsRegion) as regions_used
    values(instance_type) as types
    sum(is_large) as large_launches
    by userIdentity.arn
| where large_launches >= 1 OR count > 10
| eval risk=if(large_launches > 3,"HIGH","MEDIUM")
| table userIdentity.arn count regions_used large_launches types risk`,

  policy_bypass: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DeleteServiceControlPolicy","DetachPolicy",
                  "PutBucketPublicAccessBlock","DeletePublicAccessBlock",
                  "DisableMFADelete","UpdateAccountPasswordPolicy",
                  "DeleteAccountPublicAccessBlock")
| stats count values(eventName) as bypass_actions
    dc(eventName) as bypass_types
    by userIdentity.arn sourceIPAddress
| eval severity=case(
    like(mvjoin(bypass_actions," "),"%SCP%"), "CRITICAL",
    like(mvjoin(bypass_actions," "),"%MFA%"), "HIGH",
    true(),                                    "MEDIUM")
| table userIdentity.arn sourceIPAddress bypass_actions bypass_types severity count`,

  account_create: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateUser","CreateAccessKey","CreateLoginProfile",
                  "CreateAccount","InviteAccountToOrganization")
| stats count as creation_count
    values(eventName) as actions
    values(requestParameters.userName) as users_created
    by userIdentity.arn
| where creation_count >= 2
| eval risk=if(creation_count >= 5,"HIGH","MEDIUM")
| table userIdentity.arn creation_count actions users_created risk`,

  log_tamper: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("StopLogging","DeleteTrail","UpdateTrail",
                  "DeleteLogGroup","PutRetentionPolicy",
                  "DeleteDetector","DisassociateFromMasterAccount")
| eval is_critical=if(eventName IN ("StopLogging","DeleteTrail","DeleteDetector"),1,0)
| stats count sum(is_critical) as critical_actions
    values(eventName) as tamper_events
    by userIdentity.arn sourceIPAddress
| eval severity=if(critical_actions >= 1,"CRITICAL","HIGH")
| table userIdentity.arn sourceIPAddress count critical_actions tamper_events severity`,

  financial_manip: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("ModifyReservedInstances","PurchaseSavingsPlansOffering",
                  "DeleteCostAllocationTag","UpdateCostAllocationTagsStatus",
                  "CreateBillingGroup","DeleteBillingGroup","AssociateAccounts")
| stats count values(eventName) as events
    by userIdentity.arn sourceIPAddress
| eval flag="Billing Manipulation"
| table userIdentity.arn sourceIPAddress events count flag`,

  recon: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DescribeInstances","ListBuckets","DescribeVpcs","ListFunctions",
                  "DescribeDBInstances","ListRoles","ListUsers","DescribeSecurityGroups",
                  "GetAccountAuthorizationDetails","ListPolicies","DescribeStacks",
                  "DescribeImages","DescribeVolumes","DescribeSnapshots")
| stats count as api_count
    dc(eventName) as unique_apis
    dc(eventSource) as services_probed
    values(eventName) as calls_made
    by userIdentity.arn sourceIPAddress
| where api_count > 50 AND unique_apis >= 5
| eval risk=case(
    services_probed > 8, "CRITICAL",
    services_probed > 5, "HIGH",
    unique_apis > 10,    "MEDIUM",
    true(),              "LOW")
| table userIdentity.arn sourceIPAddress api_count unique_apis services_probed risk`,

  credential_harvest: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetSessionToken","AssumeRoleWithWebIdentity",
                  "GetFederationToken","CreateAccessKey",
                  "ListAccessKeys","GetAccessKeyLastUsed")
| stats count as cred_ops
    dc(eventName) as op_types
    values(eventName) as operations
    by userIdentity.arn sourceIPAddress
| where cred_ops > 5 OR op_types >= 3
| eval risk=if(cred_ops > 20,"HIGH","MEDIUM")
| table userIdentity.arn sourceIPAddress cred_ops op_types operations risk`,

  sensitive_access: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
| lookup sensitive_resources resource_arn AS requestParameters.bucketName
    OUTPUT sensitivity_level resource_owner
| where isnotnull(sensitivity_level)
| stats count dc(requestParameters.bucketName) as sensitive_resources_touched
    values(requestParameters.bucketName) as resources
    values(sensitivity_level) as levels
    by userIdentity.arn sourceIPAddress
| eval risk=case(
    like(mvjoin(levels," "),"RESTRICTED"), "CRITICAL",
    sensitive_resources_touched > 5,       "HIGH",
    true(),                                "MEDIUM")
| table userIdentity.arn sourceIPAddress count sensitive_resources_touched resources levels risk`,

  lateral_move: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName="AssumeRole"
| rex field=userIdentity "\"arn\":\"(?<caller_arn>[^\"]+)\""
| rex field=requestParameters "\"roleArn\":\"(?<assumed_role>[^\"]+)\""
| eval cross_acct=if(
    mvindex(split(caller_arn,":"),4)!=mvindex(split(assumed_role,":"),4),1,0)
| stats count dc(assumed_role) as roles_assumed
    values(assumed_role) as role_chain
    sum(cross_acct) as cross_account_count
    by caller_arn sourceIPAddress
| where roles_assumed >= 3 OR cross_account_count >= 2
| eval risk=case(
    cross_account_count > 3, "CRITICAL",
    roles_assumed > 5,       "HIGH",
    true(),                  "MEDIUM")
| table caller_arn sourceIPAddress roles_assumed cross_account_count role_chain risk`,

  c2_comms: () => `index=aws_vpcflow sourcetype=aws:cloudwatchlogs:vpcflow
    action=ACCEPT
| eval dest_internal=if(
    match(dstaddr,"^10\\.|^172\\.(1[6-9]|2[0-9]|3[01])\\.|^192\\.168\\."),1,0)
| where dest_internal=0
| stats count as conn_count
    dc(dstaddr) as unique_dests
    dc(dstport) as port_diversity
    sum(bytes) as total_bytes
    by srcaddr
| where (conn_count > 100 AND unique_dests > 10) OR
        (port_diversity >= 5 AND total_bytes > 10485760)
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=case(
    unique_dests > 50, "CRITICAL",
    unique_dests > 20, "HIGH",
    true(),            "MEDIUM")
| table srcaddr conn_count unique_dests port_diversity total_mb risk`,

  persistence: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateUser","CreateAccessKey","CreateLoginProfile",
                  "PutUserPolicy","AttachUserPolicy",
                  "CreateRole","UpdateAssumeRolePolicy",
                  "CreateSchedule","PutRule","PutTargets")
| eval persist_type=case(
    eventName IN ("CreateUser","CreateLoginProfile","CreateAccessKey"), "New Identity",
    eventName IN ("PutUserPolicy","AttachUserPolicy","UpdateAssumeRolePolicy"), "Policy Backdoor",
    eventName IN ("CreateSchedule","PutRule","PutTargets"), "Scheduled Persistence",
    true(), "Other")
| stats count dc(persist_type) as mechanism_count
    values(eventName) as actions
    values(persist_type) as mechanisms
    by userIdentity.arn sourceIPAddress
| where count >= 2 OR mechanism_count >= 2
| eval risk=case(
    mechanism_count >= 3, "CRITICAL",
    mechanism_count >= 2, "HIGH",
    true(),               "MEDIUM")
| table userIdentity.arn sourceIPAddress count mechanism_count mechanisms actions risk`,

  // === DATA MANIPULATION ===
  report_falsify: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutObject","CopyObject","UpdateItem","ModifyDBInstance")
| rex field=requestParameters "(?i)(report|financial|ledger|reconciliation|compliance|audit)"
| stats count as modify_count
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where modify_count > 5
| eval risk=if(modify_count > 20, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress modify_count actions risk`,

  model_poison: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutObject","CreateTrainingJob","UpdateEndpoint","CreateModel")
    eventSource="sagemaker.amazonaws.com"
| stats count as ml_ops
    dc(eventName) as ops_types
    values(requestParameters.trainingJobName) as jobs
    by userIdentity.arn sourceIPAddress
| where ml_ops > 3 OR ops_types >= 2
| eval risk=if(ops_types >= 3, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress ml_ops ops_types jobs risk`,

  txn_manip: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutItem","UpdateItem","TransactWriteItems","ExecuteStatement")
    eventSource="dynamodb.amazonaws.com"
| stats count as txn_count
    dc(eventName) as txn_types
    values(requestParameters.tableName) as tables
    by userIdentity.arn sourceIPAddress
| where txn_count > 50 AND txn_types >= 2
| eval risk=if(txn_count > 500, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress txn_count txn_types tables risk`,

  record_alter: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("UpdateItem","PutItem","ModifyDBInstance","ModifyDBSnapshot","RestoreDBInstanceFromDBSnapshot")
| stats count as alter_count
    dc(eventName) as alter_types
    values(requestParameters.tableName) as targets
    by userIdentity.arn sourceIPAddress
| where alter_count > 10 AND alter_types >= 2
| eval risk=case(alter_count > 100, "CRITICAL", alter_types >= 4, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress alter_count alter_types targets risk`,

  data_poison: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutObject","BatchPutItem","PutRecord","CreateDataSet","ImportData")
| stats count as write_count
    dc(eventName) as write_methods
    dc(requestParameters.bucketName) as targets
    by userIdentity.arn sourceIPAddress
| where write_count > 100 AND write_methods >= 2
| eval risk=if(write_count > 1000, "CRITICAL", "HIGH")
| table userIdentity.arn sourceIPAddress write_count write_methods targets risk`,

  metric_manip: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutDashboard","PutMetricAlarm","PutCompositeAlarm","DeleteAlarms","PutMetricData")
    eventSource="cloudwatch.amazonaws.com"
| stats count as metric_ops
    dc(eventName) as ops_types
    by userIdentity.arn sourceIPAddress
| where metric_ops > 3
| eval risk=if(like(mvjoin(values(eventName)," "),"%DeleteAlarms%"),"CRITICAL","HIGH")
| table userIdentity.arn sourceIPAddress metric_ops ops_types risk`,

  // === EXTENDED IT SABOTAGE ===
  ransomware_deploy: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("Encrypt","CreateGrant","PutKeyPolicy","ReEncryptTo","ReEncryptFrom")
    eventSource="kms.amazonaws.com"
| stats count as encrypt_ops
    dc(eventName) as encrypt_methods
    values(requestParameters.keyId) as keys
    by userIdentity.arn sourceIPAddress
| where encrypt_ops > 50 OR encrypt_methods >= 3
| eval risk=if(encrypt_ops > 500, "CRITICAL", "HIGH")
| table userIdentity.arn sourceIPAddress encrypt_ops encrypt_methods keys risk`,

  system_overload: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("RunInstances","CreateFunction","InvokeFunction","CreateLoadBalancer","CreateAutoScalingGroup")
| stats count as launch_count
    dc(instanceType) as instance_types
    sum(eval(if(match(instanceType,"(p3|p4|g4|g5|metal)"),1,0))) as gpu_instances
    by userIdentity.arn awsRegion
| where launch_count > 50 OR gpu_instances > 5
| eval risk=case(gpu_instances > 20, "CRITICAL", launch_count > 200, "HIGH", true(), "MEDIUM")
| table userIdentity.arn awsRegion launch_count gpu_instances instance_types risk`,

  // === EXTENDED IP THEFT ===
  email_exfil: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("SendEmail","SendRawEmail","SendBulkTemplatedEmail")
    eventSource="ses.amazonaws.com"
| stats count as email_count
    sum(eval(len(coalesce(requestParameters.rawMessage,'')))) as total_size
    by userIdentity.arn sourceIPAddress
| where email_count > 10 OR total_size > 26214400
| eval total_mb=round(total_size/1048576,2)
| eval risk=if(total_mb > 100, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress email_count total_mb risk`,

  print_exfil: () => `| comment "Print exfiltration has no direct AWS analog. Use on-prem print server logs for this detection. For AWS, monitor CloudTrail for unusual S3 GetObject activity correlated with off-hours access as a proxy indicator."`,

  cloud_sync: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateBucket","PutBucketPolicy","PutBucketAcl","PutPublicAccessBlock")
| rex field=requestParameters "(?i)(public|everyone|allUsers|authenticatedUsers)"
| stats count as sync_ops
    values(eventName) as actions
    dc(requestParameters.bucketName) as buckets_created
    by userIdentity.arn sourceIPAddress
| where like(mvjoin(actions," "),"%Public%") OR buckets_created > 5
| eval risk=if(like(mvjoin(actions," "),"%Public%"),"HIGH","MEDIUM")
| table userIdentity.arn sourceIPAddress sync_ops buckets_created actions risk`,

  screen_capture: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetConsoleScreenshot","GetInstanceScreenshot")
| stats count as screenshot_count
    values(requestParameters.instanceId) as instances
    by userIdentity.arn sourceIPAddress
| where screenshot_count > 5
| eval risk="MEDIUM"
| table userIdentity.arn sourceIPAddress screenshot_count instances risk`,

  // === EXTENDED FRAUD ===
  payroll_manip: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("UpdateItem","PutItem","ModifyInstanceAttribute")
| rex field=requestParameters "(?i)(salary|payroll|compensation|bonus|commission|direct.*deposit|bank.*account)"
| stats count as hr_touches
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where count > 5
| eval risk=if(count > 20, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress count actions risk`,

  vendor_collusion: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateVendor","UpdateVendor","ApprovePayment","CreatePurchaseOrder","AcceptAgreement")
    eventSource IN ("aws-marketplace.amazonaws.com","aws-purchase-orders.amazonaws.com")
| stats count as vendor_ops
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where vendor_ops > 3
| eval risk=if(vendor_ops > 10, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress vendor_ops actions risk`,

  expense_fraud: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateExpenseReport","ApproveExpenseReport","SubmitReceipt")
| stats count as expense_ops
    dc(requestParameters.expenseReportId) as reports
    by userIdentity.arn sourceIPAddress
| where expense_ops > 3 AND reports > 1
| eval risk=if(reports > 5, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress expense_ops reports risk`,

  // === EXTENDED ESPIONAGE ===
  document_hoarding: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetObject","HeadObject","ListObjects","DescribeDBInstances","Query","Scan")
| stats count as access_count
    dc(requestParameters.bucketName) as buckets_touched
    dc(eventName) as access_types
    by userIdentity.arn sourceIPAddress
| where access_count > 500 AND buckets_touched > 10
| eval risk=case(buckets_touched > 50, "CRITICAL", access_count > 2000, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress access_count buckets_touched access_types risk`,

  meeting_infil: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateMeeting","JoinMeeting","StartMeetingTranscription","CreateAttendee")
    eventSource="chime.amazonaws.com"
| stats count as meeting_ops
    dc(eventName) as meeting_actions
    by userIdentity.arn sourceIPAddress
| where meeting_ops > 10
| eval risk=if(meeting_actions >= 3, "MEDIUM", "LOW")
| table userIdentity.arn sourceIPAddress meeting_ops meeting_actions risk`,

  // === THIRD PARTY ===
  vendor_abuse: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    userIdentity.arn="*assumed-role*" OR userIdentity.arn="*vendor*" OR userIdentity.arn="*partner*" OR userIdentity.arn="*third-party*"
| stats count as api_count
    dc(eventName) as unique_apis
    dc(awsRegion) as regions_accessed
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where api_count > 100 AND regions_accessed > 1
| eval risk=if(regions_accessed > 3, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress api_count unique_apis regions_accessed risk`,

  msp_pivot: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName="AssumeRole"
    userIdentity.arn="*msp*" OR userIdentity.arn="*service-provider*" OR userIdentity.arn="*managed-service*"
| stats count as assume_count
    dc(requestParameters.roleArn) as roles_assumed
    values(requestParameters.roleArn) as role_chain
    by userIdentity.arn sourceIPAddress
| where assume_count > 20 OR roles_assumed > 3
| eval risk=if(roles_assumed > 5, "CRITICAL", "HIGH")
| table userIdentity.arn sourceIPAddress assume_count roles_assumed role_chain risk`,

  credential_share: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetSessionToken","AssumeRole","AssumeRoleWithSAML","AssumeRoleWithWebIdentity")
| stats count as token_count
    dc(sourceIPAddress) as unique_ips
    dc(userAgent) as unique_agents
    by userIdentity.arn
| where unique_ips > 3 OR unique_agents > 5
| eval risk=if(unique_ips > 5, "HIGH", "MEDIUM")
| table userIdentity.arn token_count unique_ips unique_agents risk`,

  partner_scrape: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetObject","ListObjects","BatchGetItem","Query","Scan")
    userIdentity.arn="*partner*" OR userIdentity.arn="*supplier*" OR userIdentity.arn="*customer*"
| stats count as read_count
    sum(bytessent) as total_bytes
    dc(requestParameters.bucketName) as buckets_read
    by userIdentity.arn sourceIPAddress
| where read_count > 1000 OR total_bytes > 524288000
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=if(total_bytes > 1073741824, "CRITICAL", "HIGH")
| table userIdentity.arn sourceIPAddress read_count total_mb buckets_read risk`,

  supply_chain_insert: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateUser","CreateAccessKey","PutUserPolicy","CreateRole","UpdateAssumeRolePolicy","CreateFunction","PutRule","UpdateFunctionCode","CreateKey")
    userIdentity.arn="*contractor*" OR userIdentity.arn="*vendor*" OR userIdentity.arn="*third-party*"
| stats count as insertion_count
    dc(eventName) as insertion_types
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where insertion_count >= 2
| eval risk=case(insertion_types >= 3, "CRITICAL", insertion_count >= 5, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress insertion_count insertion_types actions risk`,

  off_hours_contractor: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    userIdentity.arn="*contractor*" OR userIdentity.arn="*vendor*" OR userIdentity.arn="*third-party*"
| eval hour=strftime(_time,"%H"), dow=strftime(_time,"%A")
| where hour < 7 OR hour > 19 OR dow IN ("Saturday","Sunday")
| stats count as off_hours_count
    dc(eventName) as unique_apis
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where off_hours_count > 10
| eval risk=if(off_hours_count > 50, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress off_hours_count unique_apis actions risk`,

  // === UNAUTHORIZED DISCLOSURE ===
  media_leak: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetObject","HeadObject","BatchGetItem","Query")
| lookup sensitive_resources resource_arn AS requestParameters.bucketName OUTPUT sensitivity_level
| where sensitivity_level IN ("RESTRICTED","CONFIDENTIAL")
| stats count as access_count
    dc(requestParameters.bucketName) as sensitive_buckets
    values(sensitivity_level) as levels
    by userIdentity.arn sourceIPAddress
| where access_count > 20
| eval risk=case(like(mvjoin(levels," "),"RESTRICTED%"), "CRITICAL", access_count > 100, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress access_count sensitive_buckets levels risk`,

  whistleblower_collect: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetObject","ListObjects","HeadObject","GetItem","BatchGetItem","Query","Scan")
| stats count as collection_count
    dc(eventName) as collection_methods
    dc(requestParameters.bucketName) as data_sources
    values(requestParameters.bucketName) as sources
    by userIdentity.arn sourceIPAddress
| where collection_count > 200 AND collection_methods >= 3
| eval risk=case(data_sources > 20, "CRITICAL", collection_count > 1000, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress collection_count collection_methods data_sources risk`,

  social_media_post: () => `| comment "Social media disclosure detection requires web proxy/DLP logs. Use the On-Prem SPL block for proxy-based detection. For AWS, monitor CloudTrail for unusual S3 object accesses combined with off-hours activity as a proxy indicator."`,

  competitor_transfer: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetObject","GitPull","GetRepository","GetSecretValue","ListAccessKeys")
| stats count as transfer_count
    dc(eventName) as transfer_methods
    sum(bytessent) as total_bytes
    values(requestParameters.bucketName) as resources
    by userIdentity.arn sourceIPAddress
| where transfer_count > 100 OR total_bytes > 104857600
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=case(transfer_methods >= 4, "CRITICAL", total_bytes > 1073741824, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress transfer_count transfer_methods total_mb resources risk`,

  cert_manipulation: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("ImportCertificate","DeleteCertificate","UpdateCertificate","CreateKey","PutKeyPolicy")
    eventSource IN ("acm.amazonaws.com","acm-pca.amazonaws.com","kms.amazonaws.com")
| stats count as cert_ops
    dc(eventName) as ops_types
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where cert_ops > 3
| eval risk=case(like(mvjoin(actions," "),"%DeleteCertificate%"), "CRITICAL", ops_types >= 3, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress cert_ops ops_types actions risk`,

  network_reconfig: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateRoute","ReplaceRoute","DeleteRoute","CreateNetworkAclEntry","AuthorizeSecurityGroupIngress","RevokeSecurityGroupEgress","ModifyVpcAttribute","AssociateRouteTable","DeleteInternetGateway","ModifySubnetAttribute")
| stats count as net_ops
    dc(eventName) as ops_types
    dc(awsRegion) as regions_affected
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where net_ops > 10 AND ops_types >= 3
| eval risk=case(like(mvjoin(actions," "),"%DeleteInternetGateway%"), "CRITICAL", regions_affected > 2, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress net_ops ops_types regions_affected actions risk`,

  database_dump: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateDBSnapshot","ShareDBSnapshot","ModifyDBSnapshotAttribute","ExportDBSnapshot","RestoreDBInstanceFromDBSnapshot")
    eventSource="rds.amazonaws.com"
| rex field=requestParameters "(?i)(public|shared|export)"
| stats count as dump_ops
    dc(eventName) as ops_types
    values(requestParameters.dBInstanceIdentifier) as targets
    by userIdentity.arn sourceIPAddress
| where dump_ops > 2 OR like(mvjoin(values(eventName)," "),"%Share%")
| eval risk=case(like(mvjoin(values(eventName)," "),"%ShareDBSnapshot%"), "CRITICAL", ops_types >= 3, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress dump_ops ops_types targets risk`,

  backdoor_maintenance: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("CreateAccessKey","CreateLoginProfile","PutUserPolicy","AttachUserPolicy","CreateRole","UpdateAssumeRolePolicy","CreateUser")
    userIdentity.arn="*contractor*" OR userIdentity.arn="*vendor*"
| stats count as persist_ops
    dc(eventName) as persist_methods
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where persist_ops >= 1
| eval risk=case(persist_methods >= 3, "CRITICAL", persist_ops >= 2, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress persist_ops persist_methods actions risk`,

  evidence_destruction: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DeleteObject","DeleteObjects","DeleteBucket","DeleteTrail","DeleteLogGroup","DeleteDBSnapshot","DeleteSnapshot","DeleteBackup")
| stats count as destroy_count
    dc(eventName) as destroy_methods
    dc(requestParameters.bucketName) as targets
    values(eventName) as actions
    by userIdentity.arn sourceIPAddress
| where destroy_count > 10 AND destroy_methods >= 2
| eval risk=case(like(mvjoin(actions," "),"%DeleteTrail%"), "CRITICAL", destroy_count > 100, "CRITICAL", destroy_methods >= 4, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress destroy_count destroy_methods targets actions risk`,

  regulatory_filing_manip: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("PutObject","CopyObject","UpdateItem","PutItem")
| rex field=requestParameters "(?i)(sec|ftc|filing|regulatory|disclosure|10-?[KQ]|8-?K|S-?1)"
| stats count as filing_ops
    values(eventName) as actions
    dc(requestParameters.bucketName) as resources
    by userIdentity.arn sourceIPAddress
| where filing_ops > 3
| eval risk=if(filing_ops > 10, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress filing_ops resources actions risk`,

  digital_stalking: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("DescribeInstances","ListUsers","ListRoles","GetUser","GetLoginProfile","ListAccessKeys")
| stats count as lookup_count
    dc(eventName) as lookup_types
    dc(sourceIPAddress) as unique_ips
    by userIdentity.arn
| where lookup_count > 30 AND lookup_types >= 3
| eval risk=case(lookup_count > 100, "HIGH", "MEDIUM")
| table userIdentity.arn lookup_count lookup_types unique_ips risk`,

  threat_comms: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("SendEmail","SendRawEmail")
    eventSource="ses.amazonaws.com"
| rex field=requestParameters "(?i)(threat|kill|harm|hurt|die|attack|destroy|ruin|expose|leak)"
| stats count as threat_count
    dc(requestParameters.destination) as unique_targets
    by userIdentity.arn sourceIPAddress
| where threat_count > 0
| eval risk=case(threat_count > 5, "CRITICAL", unique_targets > 1, "HIGH", true(), "MEDIUM")
| table userIdentity.arn sourceIPAddress threat_count unique_targets risk`,

  unauthorized_surveillance: () => `index=aws_cloudtrail sourcetype=aws:cloudtrail
    eventName IN ("GetConsoleScreenshot","GetInstanceScreenshot","StartMeetingTranscription","CreateAttendee","JoinMeeting")
| stats count as surveil_ops
    dc(eventName) as surveil_methods
    values(requestParameters.instanceId) as targets
    by userIdentity.arn sourceIPAddress
| where surveil_ops > 3
| eval risk=if(surveil_methods >= 2, "HIGH", "MEDIUM")
| table userIdentity.arn sourceIPAddress surveil_ops surveil_methods targets risk`,

};

// ═══════════════════════════════════
// SPL TEMPLATES — ON-PREM
// ═══════════════════════════════════

export const ONPREM_SPL: Record<string, () => string> = {
  delete_data: () => `index=wineventlog EventCode=4663
    Object_Type=File
    (Access_Mask=0x10000 OR Access_Mask=0x40000)
| stats count as delete_count
    dc(Object_Name) as unique_files
    values(Object_Name) as files
    by SubjectUserName SubjectDomainName IpAddress
| where delete_count > 50
| eval risk=case(
    delete_count > 500, "CRITICAL",
    delete_count > 100, "HIGH",
    true(),             "MEDIUM")
| table SubjectUserName SubjectDomainName IpAddress delete_count unique_files risk`,

  resource_destroy: () => `index=crowdstrike sourcetype=crowdstrike:events:CommandHistory
    (CommandLine="*del /f*" OR CommandLine="*rm -rf*" OR
     CommandLine="*Remove-Item*" OR CommandLine="*Format-*" OR
     CommandLine="*wipe*")
| stats count as cmd_count
    values(CommandLine) as commands
    dc(ComputerName) as systems_affected
    by UserName
| where cmd_count > 5
| eval risk=if(systems_affected > 1,"HIGH","MEDIUM")
| table UserName cmd_count systems_affected commands risk`,

  config_tamper: () => `index=wineventlog EventCode IN (4719,4739,4902,4904,4905,4906,4907,4912)
| eval change_type=case(
    EventCode=4719, "Audit Policy Change",
    EventCode=4739, "Domain Policy Change",
    EventCode IN (4902,4904,4905,4906,4907,4912), "Per-User Audit Policy")
| stats count values(change_type) as changes
    dc(EventCode) as change_types
    by SubjectUserName ComputerName
| where count >= 2
| eval severity=if(change_types >= 3,"HIGH","MEDIUM")
| table SubjectUserName ComputerName changes change_types severity count`,

  logic_bomb: () => `index=wineventlog EventCode IN (4698,4702,4699,4700,4701)
| eval task_action=case(
    EventCode=4698, "Scheduled Task Created",
    EventCode=4702, "Scheduled Task Updated",
    EventCode=4699, "Scheduled Task Deleted",
    EventCode IN (4700,4701), "Task Enabled/Disabled")
| stats count values(task_action) as actions
    values(TaskName) as task_names
    by SubjectUserName ComputerName
| where count >= 2
| table SubjectUserName ComputerName actions task_names count`,

  backup_destroy: () => `index=crowdstrike sourcetype=crowdstrike:events:CommandHistory
    (CommandLine="*vssadmin delete*" OR
     CommandLine="*wbadmin delete*" OR
     CommandLine="*bcdedit*bootstatuspolicy*" OR
     CommandLine="*diskshadow*delete*")
| stats count as cmd_count
    values(CommandLine) as commands
    by UserName ComputerName
| eval severity="CRITICAL"
| table UserName ComputerName cmd_count commands severity`,

  access_revoke: () => `index=wineventlog EventCode IN (4726,4743,4758,4764,4729,4733)
| eval action_type=case(
    EventCode=4726, "User Account Deleted",
    EventCode=4743, "Computer Account Deleted",
    EventCode IN (4758,4764), "Security Group Modified",
    EventCode IN (4729,4733), "Member Removed from Group")
| stats count as action_count
    values(action_type) as actions
    dc(TargetUserName) as targets_affected
    by SubjectUserName SubjectDomainName
| where action_count >= 3
| table SubjectUserName SubjectDomainName action_count targets_affected actions`,

  s3_exfil: () => `index=symantec_dlp sourcetype=symantec:dlp:incidents
    Severity IN ("High","Critical")
    (rule_name="*cloud*" OR rule_name="*upload*" OR rule_name="*transfer*")
| stats count as violation_count
    sum(file_size) as total_bytes
    dc(file_name) as unique_files
    values(destination) as destinations
    by user_name endpoint_name
| where violation_count > 5 OR total_bytes > 52428800
| eval total_mb=round(total_bytes/1048576,2)
| table user_name endpoint_name violation_count unique_files total_mb destinations`,

  repo_clone: () => `index=proxy sourcetype=proxy
    (url="*github.com*" OR url="*gitlab.com*" OR url="*bitbucket.org*")
    (cs_method=GET OR cs_method=POST)
    sc_bytes > 1048576
| stats count as req_count
    sum(sc_bytes) as total_bytes
    dc(url) as unique_repos
    values(url) as repos
    by c_ip cs_username
| where total_bytes > 52428800
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=if(total_bytes > 524288000,"HIGH","MEDIUM")
| table cs_username c_ip req_count unique_repos total_mb repos risk`,

  secrets_access: () => `index=crowdstrike sourcetype=crowdstrike:events:FileAccess
    (FileName="*password*" OR FileName="*credential*" OR
     FileName="*.kdbx" OR FileName="*secret*" OR
     FileName="*vault*" OR FileName="*.pfx" OR FileName="*.p12")
| stats count as access_count
    dc(FileName) as unique_files
    values(FileName) as files_accessed
    by UserName ComputerName
| where access_count > 5
| eval risk=if(unique_files > 3,"HIGH","MEDIUM")
| table UserName ComputerName access_count unique_files files_accessed risk`,

  data_stage: () => `index=symantec_dlp sourcetype=symantec:dlp:incidents
    (rule_name="*removable*" OR rule_name="*personal*" OR
     rule_name="*cloud storage*" OR rule_name="*webmail*")
| stats count as violation_count
    sum(file_size) as total_bytes
    values(destination_type) as dest_types
    values(file_name) as files
    by user_name endpoint_name
| where violation_count >= 2
| eval total_mb=round(total_bytes/1048576,2)
| table user_name endpoint_name violation_count total_mb dest_types files`,

  cross_account: () => `index=proxy sourcetype=proxy
    cs_username=*
| stats count as req_count
    dc(cs_host) as unique_domains
    sum(sc_bytes) as total_bytes
    values(cs_host) as domains
    by cs_username c_ip
| where unique_domains > 20 AND total_bytes > 104857600
| eval total_mb=round(total_bytes/1048576,2)
| lookup known_corp_domains domain AS cs_host OUTPUT is_corp
| where is_corp!="true" OR isnull(is_corp)
| table cs_username c_ip req_count unique_domains total_mb domains`,

  usb_exfil: () => `index=wineventlog EventCode IN (4663,6416)
| eval removable=if(
    match(Object_Name,"(?i)\\\\[A-Z]:\\\\") AND
    NOT match(Object_Name,"(?i)(C:|D:|system32|programfiles)"),1,0)
| where removable=1
| stats count as file_count
    sum(eval(len(Object_Name))) as data_indicator
    dc(Object_Name) as unique_files
    values(Object_Name) as files
    by SubjectUserName IpAddress ComputerName
| where file_count > 20
| eval risk=if(file_count > 100,"HIGH","MEDIUM")
| table SubjectUserName ComputerName IpAddress file_count unique_files risk

| append [
    index=crowdstrike sourcetype=crowdstrike:events:RemovableMedia
    | stats count as usb_events
        values(DeviceSerialNumber) as devices
        dc(FileName) as files_transferred
        by UserName ComputerName
    | where usb_events > 10
    | table UserName ComputerName usb_events files_transferred devices]`,

  priv_escalation: () => `index=wineventlog EventCode IN (4728,4732,4756,4720,4722,4724,4738)
    (EventCode!=4720 OR MemberName="*")
| eval escalation_type=case(
    EventCode IN (4728,4732,4756), "Added to Privileged Group",
    EventCode=4720,                "New Account Created",
    EventCode IN (4722,4724),      "Account Enabled/Password Reset",
    EventCode=4738,                "Account Properties Changed")
| stats count dc(escalation_type) as type_count
    values(escalation_type) as types
    values(TargetUserName) as targets
    by SubjectUserName SubjectDomainName
| where count >= 2 OR like(mvjoin(types," "),"Privileged%")
| eval severity=case(
    type_count >= 3,                           "CRITICAL",
    like(mvjoin(types," "),"Privileged%"),     "HIGH",
    true(),                                    "MEDIUM")
| table SubjectUserName SubjectDomainName count type_count types targets severity`,

  resource_abuse: () => `index=crowdstrike sourcetype=crowdstrike:events:CommandHistory
    (CommandLine="*Install-Module*" OR CommandLine="*choco install*" OR
     CommandLine="*winget install*" OR CommandLine="*msiexec*" OR
     CommandLine="*setup.exe*")
| stats count as install_count
    values(CommandLine) as commands
    dc(ComputerName) as systems
    by UserName
| where install_count > 5
| eval risk=if(systems > 1,"HIGH","MEDIUM")
| table UserName install_count systems commands risk`,

  policy_bypass: () => `index=wineventlog EventCode IN (4719,4907,4670,4704,4705)
| eval bypass_type=case(
    EventCode=4719, "Audit Policy Disabled",
    EventCode=4907, "Object Audit Policy Changed",
    EventCode=4670, "Permissions Changed",
    EventCode IN (4704,4705), "User Right Assigned/Removed")
| stats count values(bypass_type) as bypass_events
    dc(EventCode) as bypass_types
    by SubjectUserName ComputerName
| where count >= 2
| eval severity=case(
    bypass_types >= 3, "HIGH",
    true(),            "MEDIUM")
| table SubjectUserName ComputerName count bypass_types bypass_events severity`,

  account_create: () => `index=wineventlog EventCode IN (4720,4722,4723,4724,4725,4726)
| eval create_action=case(
    EventCode=4720, "Account Created",
    EventCode=4722, "Account Enabled",
    EventCode=4723, "Password Change Attempt",
    EventCode=4724, "Password Reset",
    EventCode=4725, "Account Disabled",
    EventCode=4726, "Account Deleted")
| stats count as action_count
    dc(TargetUserName) as accounts_touched
    values(create_action) as actions
    by SubjectUserName SubjectDomainName
| where action_count >= 3
| table SubjectUserName SubjectDomainName action_count accounts_touched actions`,

  log_tamper: () => `index=wineventlog EventCode IN (1102,1100,4612,4621)
| eval tamper_type=case(
    EventCode=1102, "Audit Log Cleared",
    EventCode=1100, "Event Logging Stopped",
    EventCode=4612, "Audit Log Resources Exhausted",
    EventCode=4621, "Admin Recovered System")
| stats count values(tamper_type) as events
    by SubjectUserName ComputerName
| eval severity="CRITICAL"
| table SubjectUserName ComputerName events count severity`,

  financial_manip: () => `index=proxy sourcetype=proxy
    (url="*bank*" OR url="*paypal*" OR url="*wire*" OR
     url="*venmo*" OR url="*zelle*" OR url="*crypto*exchange*")
    cs_username=* NOT (cs_categories="*financial*" AND sc_bytes < 100000)
| stats count as visit_count
    sum(sc_bytes) as total_bytes
    dc(cs_host) as unique_fin_sites
    values(cs_host) as sites
    by cs_username c_ip
| where visit_count > 20 AND unique_fin_sites > 3
| table cs_username c_ip visit_count unique_fin_sites sites`,

  recon: () => `index=wineventlog EventCode IN (4661,4662,4674,4688)
    (ObjectName="*CN=Users*" OR ObjectName="*CN=Computers*" OR
     ObjectName="*CN=Admins*" OR CommandLine="*net user*" OR
     CommandLine="*net group*" OR CommandLine="*whoami*" OR
     CommandLine="*nltest*" OR CommandLine="*dsquery*")
| stats count as recon_count
    dc(EventCode) as event_types
    values(CommandLine) as commands
    by SubjectUserName WorkstationName
| where recon_count > 20
| eval risk=case(
    event_types > 4, "HIGH",
    recon_count > 50,"MEDIUM",
    true(),          "LOW")
| table SubjectUserName WorkstationName recon_count event_types commands risk`,

  credential_harvest: () => `index=crowdstrike sourcetype=crowdstrike:events:ProcessRollup2
    (ImageFileName="*mimikatz*" OR ImageFileName="*procdump*" OR
     ImageFileName="*sekurlsa*" OR CommandLine="*lsass*" OR
     CommandLine="*SAM*" OR CommandLine="*ntds.dit*" OR
     CommandLine="*vaultcmd*")
| stats count as proc_count
    values(ImageFileName) as tools_used
    values(CommandLine) as commands
    by UserName ComputerName
| eval severity=case(
    like(mvjoin(tools_used," "),"mimikatz"),  "CRITICAL",
    like(mvjoin(commands," "),"lsass"),       "CRITICAL",
    true(),                                    "HIGH")
| table UserName ComputerName proc_count tools_used commands severity`,

  sensitive_access: () => `index=symantec_dlp sourcetype=symantec:dlp:incidents
    Severity IN ("High","Critical")
| lookup sensitive_classifications classification AS rule_name OUTPUT data_type data_owner
| where isnotnull(data_type)
| stats count as violation_count
    dc(rule_name) as policies_triggered
    values(data_type) as data_types
    values(file_name) as files
    by user_name endpoint_name
| where violation_count >= 1
| eval risk=case(
    policies_triggered >= 3, "CRITICAL",
    violation_count >= 5,    "HIGH",
    true(),                  "MEDIUM")
| table user_name endpoint_name violation_count policies_triggered data_types risk`,

  lateral_move: () => `index=wineventlog EventCode IN (4648,4624)
    Logon_Type IN (3,10)
| stats count as logon_count
    dc(Computer) as unique_systems
    values(Computer) as systems_accessed
    dc(LogonType) as logon_types
    by SubjectUserName SubjectDomainName IpAddress
| where unique_systems >= 3 AND logon_count > 10
| eval risk=case(
    unique_systems > 10, "CRITICAL",
    unique_systems > 5,  "HIGH",
    true(),              "MEDIUM")
| table SubjectUserName SubjectDomainName IpAddress logon_count unique_systems systems_accessed risk`,

  c2_comms: () => `index=proxy sourcetype=proxy
    NOT (cs_categories="*corporate*" OR cs_categories="*business*")
| stats count as req_count
    sum(sc_bytes) as total_bytes
    dc(cs_host) as unique_hosts
    dc(cs_ip) as unique_ips
    by cs_username c_ip
| where (req_count > 200 AND unique_hosts > 30) OR
        (total_bytes > 104857600 AND unique_hosts > 10)
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=case(
    unique_hosts > 100, "CRITICAL",
    unique_hosts > 50,  "HIGH",
    true(),             "MEDIUM")
| table cs_username c_ip req_count unique_hosts total_mb risk`,

  persistence: () => `index=wineventlog EventCode IN (4698,4702,4720,4722,4728,4732,4756)
| eval persist_type=case(
    EventCode IN (4698,4702),         "Scheduled Task",
    EventCode=4720,                   "New User Account",
    EventCode=4722,                   "Account Re-Enabled",
    EventCode IN (4728,4732,4756),    "Group Membership Change")
| stats count dc(persist_type) as mechanism_count
    values(persist_type) as mechanisms
    values(EventCode) as event_codes
    by SubjectUserName ComputerName
| where count >= 2 OR mechanism_count >= 2
| eval risk=case(
    mechanism_count >= 3, "CRITICAL",
    mechanism_count >= 2, "HIGH",
    true(),               "MEDIUM")
| table SubjectUserName ComputerName count mechanism_count mechanisms risk`,

  // === DATA MANIPULATION (On-Prem) ===
  report_falsify: () => `index=saas_finance sourcetype=saas_finance:audit
    action IN ("modify_report","export_report","schedule_report","delete_report")
| stats count as report_ops
    dc(report_name) as reports_modified
    values(action) as actions
    by user_name source_ip
| where report_ops > 5
| eval risk=if(reports_modified > 3, "HIGH", "MEDIUM")
| table user_name source_ip report_ops reports_modified actions risk`,

  model_poison: () => `index=crowdstrike sourcetype=crowdstrike:events:FileModification
    (FilePath="*model*" OR FilePath="*training*" OR FilePath="*weights*" OR FilePath="*checkpoint*")
| stats count as file_ops
    dc(FilePath) as files_touched
    values(FilePath) as files
    by UserName ComputerName
| where file_ops > 5
| eval risk=if(files_touched > 3, "HIGH", "MEDIUM")
| table UserName ComputerName file_ops files_touched files risk`,

  txn_manip: () => `index=db_audit sourcetype=db_audit
    statement_type IN ("UPDATE","INSERT","DELETE")
| rex field=sql_text "(?i)(payment|ledger|transaction|invoice|balance)"
| stats count as txn_count
    dc(table_name) as tables_touched
    by db_user client_ip
| where txn_count > 20
| eval risk=if(txn_count > 500, "HIGH", "MEDIUM")
| table db_user client_ip txn_count tables_touched risk`,

  record_alter: () => `index=db_audit sourcetype=db_audit
    statement_type IN ("UPDATE","DELETE","ALTER","TRUNCATE")
| stats count as alter_count
    dc(table_name) as tables_altered
    values(statement_type) as operations
    by db_user client_ip
| where alter_count > 10
| eval risk=case(alter_count > 100, "CRITICAL", tables_altered > 5, "HIGH", true(), "MEDIUM")
| table db_user client_ip alter_count tables_altered operations risk`,

  data_poison: () => `index=db_audit sourcetype=db_audit
    statement_type="INSERT"
| stats count as insert_count
    dc(table_name) as tables_targeted
    values(table_name) as targets
    by db_user client_ip
| where insert_count > 100
| eval risk=if(insert_count > 1000, "CRITICAL", "HIGH")
| table db_user client_ip insert_count tables_targeted targets risk`,

  metric_manip: () => `index=wineventlog EventCode=4688
    (CommandLine="*grafana*" OR CommandLine="*kibana*" OR CommandLine="*splunk*" OR CommandLine="*dashboard*")
| rex field=CommandLine "(?i)(delete|modify|update|disable|mute)"
| stats count as cmd_count
    values(CommandLine) as commands
    by SubjectUserName ComputerName
| where cmd_count > 3
| eval risk=if(cmd_count > 10, "HIGH", "MEDIUM")
| table SubjectUserName ComputerName cmd_count commands risk`,

  // === EXTENDED IT SABOTAGE (On-Prem) ===
  ransomware_deploy: () => `index=crowdstrike sourcetype=crowdstrike:events:FileModification
    (FileName="*.encrypted" OR FileName="*.lock" OR FileName="*.crypt" OR FileName="*.enc" OR FileName="*.locked")
| stats count as encrypt_count
    dc(FileName) as files_encrypted
    dc(ComputerName) as systems_affected
    by UserName
| where encrypt_count > 20
| eval risk=case(systems_affected > 5, "CRITICAL", encrypt_count > 200, "HIGH", true(), "MEDIUM")
| table UserName encrypt_count files_encrypted systems_affected risk`,

  system_overload: () => `index=crowdstrike sourcetype=crowdstrike:events:CommandHistory
    (CommandLine="*stress*" OR CommandLine="*flood*" OR CommandLine="*fork bomb*" OR CommandLine="*while true*" OR CommandLine="*yes >*")
| stats count as cmd_count
    values(CommandLine) as commands
    dc(ComputerName) as systems
    by UserName
| where cmd_count > 5
| eval risk=if(systems > 2, "HIGH", "MEDIUM")
| table UserName cmd_count systems commands risk`,

  // === EXTENDED IP THEFT (On-Prem) ===
  email_exfil: () => `index=email sourcetype=email
    direction="outbound"
| rex field=recipient "@(?<ext_domain>[^>]+)"
| lookup known_corp_domains domain AS ext_domain OUTPUT is_corp
| where is_corp!="true" OR isnull(is_corp)
| stats count as email_count
    sum(attachment_size) as total_bytes
    dc(recipient) as unique_external
    values(attachment_name) as attachments
    by sender source_ip
| where email_count > 5 OR total_bytes > 26214400
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=case(total_bytes > 104857600, "CRITICAL", email_count > 20, "HIGH", true(), "MEDIUM")
| table sender source_ip email_count unique_external total_mb attachments risk`,

  print_exfil: () => `index=print_service sourcetype=print_service
    (pages > 20 OR color_pages > 10)
| stats count as print_jobs
    sum(pages) as total_pages
    dc(document_name) as unique_docs
    values(document_name) as documents
    by user_name printer_name printer_location
| where total_pages > 100 OR unique_docs > 10
| eval risk=case(total_pages > 500, "HIGH", print_jobs > 20, "MEDIUM", true(), "LOW")
| table user_name printer_name printer_location print_jobs total_pages unique_docs risk`,

  cloud_sync: () => `index=proxy sourcetype=proxy
    (url="*dropbox.com*" OR url="*drive.google.com*" OR url="*onedrive.live.com*" OR url="*box.com*")
    NOT (cs_user_agent="*corp*" OR cs_categories="*business*")
    sc_bytes > 1048576
| stats count as sync_events
    sum(sc_bytes) as total_bytes
    dc(url) as unique_services
    by cs_username c_ip
| where total_bytes > 104857600
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=if(total_bytes > 524288000, "HIGH", "MEDIUM")
| table cs_username c_ip sync_events unique_services total_mb risk`,

  screen_capture: () => `index=crowdstrike sourcetype=crowdstrike:events:ProcessRollup2
    (ImageFileName="*snippingtool*" OR ImageFileName="*snip*" OR ImageFileName="*greenshot*" OR ImageFileName="*lightshot*" OR ImageFileName="*screenpresso*" OR ImageFileName="*obs*" OR ImageFileName="*sharex*")
| stats count as capture_events
    dc(ImageFileName) as tools_used
    values(ImageFileName) as tools
    by UserName ComputerName
| where capture_events > 10
| eval risk=if(tools_used >= 3, "HIGH", "MEDIUM")
| table UserName ComputerName capture_events tools_used tools risk`,

  // === EXTENDED FRAUD (On-Prem) ===
  payroll_manip: () => `index=saas_hr sourcetype=saas_hr:audit
    action IN ("modify_salary","modify_bonus","modify_direct_deposit","modify_compensation","add_commission")
| stats count as manip_count
    dc(action) as manip_types
    dc(employee_id) as employees_affected
    by user_name source_ip
| where manip_count >= 2
| eval risk=case(employees_affected > 5, "CRITICAL", manip_types >= 3, "HIGH", true(), "MEDIUM")
| table user_name source_ip manip_count manip_types employees_affected risk`,

  vendor_collusion: () => `index=saas_finance sourcetype=saas_finance:audit
    action IN ("create_vendor","modify_vendor","approve_invoice","create_po","modify_payment")
| stats count as vendor_ops
    dc(action) as ops_types
    dc(vendor_id) as vendors_touched
    values(vendor_name) as vendors
    by user_name source_ip
| where vendor_ops > 3 OR vendors_touched > 1
| eval risk=if(vendors_touched > 3, "HIGH", "MEDIUM")
| table user_name source_ip vendor_ops ops_types vendors_touched vendors risk`,

  expense_fraud: () => `index=saas_finance sourcetype=saas_finance:audit
    action IN ("submit_expense","approve_expense","modify_expense","duplicate_receipt")
| stats count as expense_ops
    sum(expense_amount) as total_amount
    dc(expense_report_id) as reports
    by user_name approver_name
| where expense_ops > 3 OR total_amount > 5000
| eval risk=case(total_amount > 50000, "CRITICAL", reports > 5, "HIGH", true(), "MEDIUM")
| table user_name approver_name expense_ops reports total_amount risk`,

  // === EXTENDED ESPIONAGE (On-Prem) ===
  document_hoarding: () => `index=dlp sourcetype=symantec:dlp:incidents
| stats count as access_count
    dc(file_name) as unique_docs
    sum(file_size) as total_size
    by user_name endpoint_name
| where access_count > 500 OR unique_docs > 200
| eval total_mb=round(total_size/1048576,2)
| eval risk=case(unique_docs > 1000, "CRITICAL", access_count > 2000, "HIGH", true(), "MEDIUM")
| table user_name endpoint_name access_count unique_docs total_mb risk`,

  meeting_infil: () => `index=calendar sourcetype=calendar
    (action="forward_meeting" OR action="add_external_attendee" OR action="download_recording" OR action="join_unauthorized")
| stats count as meeting_ops
    dc(meeting_id) as meetings_affected
    values(action) as actions
    by user_name source_ip
| where meeting_ops > 3
| eval risk=if(meetings_affected > 5, "HIGH", "MEDIUM")
| table user_name source_ip meeting_ops meetings_affected actions risk`,

  // === THIRD PARTY (On-Prem) ===
  vendor_abuse: () => `index=vpn sourcetype=vpn
    user_group="*vendor*" OR user_group="*contractor*" OR user_group="*partner*"
| stats count as vpn_sessions
    dc(dest_ip) as systems_accessed
    sum(session_duration) as total_minutes
    by user_name source_ip
| where systems_accessed > 10 OR total_minutes > 480
| eval risk=if(systems_accessed > 20, "HIGH", "MEDIUM")
| table user_name source_ip vpn_sessions systems_accessed total_minutes risk

| append [
    index=wineventlog EventCode=4624
    Logon_Type IN (3,10)
    SubjectUserName="*vendor*" OR SubjectUserName="*contractor*" OR SubjectUserName="*partner*"
  | stats count as logon_count
      dc(Computer) as systems
      by SubjectUserName IpAddress
  | where systems > 5
  | table SubjectUserName IpAddress logon_count systems]`,

  msp_pivot: () => `index=wineventlog EventCode=4624
    Logon_Type IN (3,10)
    SubjectUserName="*msp*" OR SubjectUserName="*managed*" OR SubjectUserName="*service*provider*"
| stats count as logon_count
    dc(Computer) as systems_accessed
    values(Computer) as systems
    by SubjectUserName IpAddress
| where systems_accessed > 3
| eval risk=if(systems_accessed > 10, "CRITICAL", "HIGH")
| table SubjectUserName IpAddress logon_count systems_accessed systems risk`,

  credential_share: () => `index=ad sourcetype=WinEventLog:Security
    EventCode=4768
| stats count as tgt_requests
    dc(ClientAddress) as unique_source_ips
    dc(ServiceName) as unique_services
    by TargetUserName
| where unique_source_ips > 3
| eval risk=if(unique_source_ips > 10, "HIGH", "MEDIUM")
| table TargetUserName tgt_requests unique_source_ips unique_services risk`,

  partner_scrape: () => `index=proxy sourcetype=proxy
    (url="*partner*portal*" OR url="*supplier*" OR url="*customer*portal*")
    sc_bytes > 1048576
| stats count as req_count
    sum(sc_bytes) as total_bytes
    dc(url) as unique_endpoints
    by cs_username c_ip
| where total_bytes > 104857600
| eval total_mb=round(total_bytes/1048576,2)
| eval risk=if(total_bytes > 524288000, "CRITICAL", "HIGH")
| table cs_username c_ip req_count unique_endpoints total_mb risk`,

  supply_chain_insert: () => `index=crowdstrike sourcetype=crowdstrike:events:ProcessRollup2
    UserName="*contractor*" OR UserName="*vendor*"
    (ImageFileName="*powershell*" OR ImageFileName="*cmd.exe" OR ImageFileName="*wscript*" OR ImageFileName="*cscript*" OR ImageFileName="*bash*" OR ImageFileName="*nc.exe" OR ImageFileName="*netcat*")
| stats count as proc_count
    values(CommandLine) as commands
    by UserName ComputerName
| where proc_count > 5
| eval risk=if(proc_count > 20, "CRITICAL", "HIGH")
| table UserName ComputerName proc_count commands risk`,

  off_hours_contractor: () => `index=physical_access sourcetype=physical_access
    user_group="*contractor*" OR user_group="*vendor*" OR user_group="*third*party*"
| eval hour=strftime(_time,"%H"), dow=strftime(_time,"%A")
| where hour < 7 OR hour > 19 OR dow IN ("Saturday","Sunday")
| stats count as badge_swipes
    dc(door_name) as zones_accessed
    values(door_name) as zones
    by user_name
| where badge_swipes > 2
| eval risk=if(zones_accessed > 5, "HIGH", "MEDIUM")
| table user_name badge_swipes zones_accessed zones risk

| append [
    index=vpn sourcetype=vpn
    user_group="*contractor*" OR user_group="*vendor*"
  | eval hour=strftime(_time,"%H"), dow=strftime(_time,"%A")
  | where hour < 7 OR hour > 19 OR dow IN ("Saturday","Sunday")
  | stats count as vpn_count
      sum(session_duration) as minutes
      by user_name source_ip
  | where minutes > 60
  | table user_name source_ip vpn_count minutes]`,

  // === UNAUTHORIZED DISCLOSURE (On-Prem) ===
  media_leak: () => `index=email sourcetype=email
    direction="outbound"
    (attachment_name="*.pdf" OR attachment_name="*.xlsx" OR attachment_name="*.docx" OR attachment_name="*.zip")
| lookup sensitive_classifications classification AS dlp_rule OUTPUT data_type
| rex field=recipient "@(?<ext_domain>[^>]+)"
| lookup known_corp_domains domain AS ext_domain OUTPUT is_corp
| where is_corp!="true" OR isnull(is_corp)
| stats count as leak_ops
    sum(attachment_size) as total_size
    dc(attachment_name) as unique_files
    by sender recipient
| where leak_ops > 3 OR total_size > 10485760
| eval total_mb=round(total_size/1048576,2)
| eval risk=case(total_mb > 100, "CRITICAL", leak_ops > 10, "HIGH", true(), "MEDIUM")
| table sender recipient leak_ops unique_files total_mb risk`,

  whistleblower_collect: () => `index=email sourcetype=email
    direction="outbound"
| rex field=recipient "@(?<ext_domain>[^>]+)"
| lookup known_corp_domains domain AS ext_domain OUTPUT is_corp
| where is_corp!="true" OR isnull(is_corp)
| stats count as collect_ops
    dc(recipient) as unique_external
    sum(attachment_size) as total_size
    dc(attachment_name) as unique_docs
    by sender source_ip
| where collect_ops > 20 OR unique_docs > 10
| eval total_mb=round(total_size/1048576,2)
| eval risk=case(unique_docs > 50, "CRITICAL", collect_ops > 100, "HIGH", true(), "MEDIUM")
| table sender source_ip collect_ops unique_external unique_docs total_mb risk

| append [
    index=dlp sourcetype=symantec:dlp:incidents
    Severity IN ("High","Critical")
  | stats count as dlp_count
      dc(file_name) as dlp_files
      values(file_name) as files
      by user_name endpoint_name
  | where dlp_count > 50
  | table user_name endpoint_name dlp_count dlp_files files]`,

  social_media_post: () => `index=proxy sourcetype=proxy
    (url="*twitter.com*" OR url="*x.com*" OR url="*facebook.com*" OR url="*linkedin.com*" OR url="*reddit.com*" OR url="*pastebin.com*" OR url="*tumblr.com*" OR url="*medium.com*")
    NOT cs_user_agent="*corp*"
    cs_method="POST"
    sc_bytes > 1024
| stats count as post_count
    dc(url) as unique_platforms
    sum(sc_bytes) as total_bytes
    values(url) as platforms
    by cs_username c_ip
| where post_count > 5
| eval risk=if(post_count > 20, "HIGH", "MEDIUM")
| table cs_username c_ip post_count unique_platforms platforms risk`,

  competitor_transfer: () => `index=dlp sourcetype=symantec:dlp:incidents
    Severity IN ("High","Critical")
| stats count as dlp_count
    sum(file_size) as total_size
    dc(file_name) as unique_files
    values(destination) as destinations
    by user_name endpoint_name
| where dlp_count > 10 OR total_size > 52428800
| eval total_mb=round(total_size/1048576,2)
| eval risk=case(total_size > 524288000, "CRITICAL", unique_files > 50, "HIGH", true(), "MEDIUM")
| table user_name endpoint_name dlp_count unique_files total_mb destinations risk

| append [
    index=proxy sourcetype=proxy
    cs_username=*
    (url="*github.com*" OR url="*gitlab.com*" OR url="*bitbucket.org*" OR url="*personal*cloud*")
    sc_bytes > 10485760
  | stats count as proxy_count
      sum(sc_bytes) as proxy_bytes
      dc(url) as unique_urls
      by cs_username c_ip
  | where proxy_bytes > 104857600
  | eval proxy_mb=round(proxy_bytes/1048576,2)
  | table cs_username c_ip proxy_count unique_urls proxy_mb]`,

  cert_manipulation: () => `index=wineventlog EventCode IN (4663,4670,5136,5137,5141)
    (ObjectName="*Certificate*" OR ObjectName="*cert*" OR ObjectName="*.pfx" OR ObjectName="*.pem")
| stats count as cert_ops
    dc(EventCode) as ops_types
    values(ObjectName) as objects
    by SubjectUserName ComputerName
| where cert_ops > 3
| eval risk=if(ops_types >= 3, "HIGH", "MEDIUM")
| table SubjectUserName ComputerName cert_ops ops_types objects risk`,

  network_reconfig: () => `index=wineventlog EventCode IN (4739,4946,4947,4948,4950,5144,5145)
| eval change_type=case(EventCode=4739,"Domain Policy Changed",EventCode IN (4946,4947,4948,4950),"Firewall Changed",EventCode IN (5144,5145),"Network Share Modified")
| stats count as change_count
    dc(change_type) as change_types
    values(change_type) as changes
    by SubjectUserName ComputerName
| where change_count > 3 AND change_types >= 2
| eval risk=case(like(mvjoin(changes," "),"Firewall%"), "HIGH", change_types >= 3, "HIGH", true(), "MEDIUM")
| table SubjectUserName ComputerName change_count change_types changes risk`,

  database_dump: () => `index=db_audit sourcetype=db_audit
    statement_type IN ("SELECT","EXPORT","BACKUP","DUMP")
| rex field=sql_text "(?i)(INTO OUTFILE|pg_dump|mysqldump|bcp|expdp|exp|datapump|backup database|COPY.*TO)"
| stats count as dump_ops
    sum(rows_returned) as total_rows
    dc(table_name) as tables_dumped
    values(table_name) as tables
    by db_user client_ip
| where dump_ops > 0
| eval risk=case(total_rows > 1000000, "CRITICAL", tables_dumped > 10, "HIGH", dump_ops > 3, "MEDIUM", true(), "LOW")
| table db_user client_ip dump_ops total_rows tables_dumped tables risk`,

  backdoor_maintenance: () => `index=ad sourcetype=WinEventLog:Security
    EventCode IN (4720,4722,4728,4732,4756,4724)
    (SubjectUserName="*contractor*" OR SubjectUserName="*vendor*" OR SubjectUserName="*partner*")
| stats count as persist_ops
    values(EventCode) as events
    dc(TargetUserName) as accounts_created
    by SubjectUserName WorkstationName
| where persist_ops >= 1
| eval risk=case(persist_ops > 5, "CRITICAL", accounts_created > 1, "HIGH", true(), "MEDIUM")
| table SubjectUserName WorkstationName persist_ops accounts_created events risk`,

  evidence_destruction: () => `index=wineventlog EventCode IN (4663,4660,1102,517)
    (Access_Mask="0x10000" OR EventCode=1102)
| eval action_type=case(EventCode=4663,"File Deleted",EventCode=4660,"Handle Closed After Delete",EventCode=1102,"Audit Log Cleared",EventCode=517,"Scheduled Task Deleted")
| stats count as destroy_count
    dc(action_type) as destroy_methods
    values(ObjectName) as targets
    by SubjectUserName ComputerName
| where destroy_count > 20 AND destroy_methods >= 2
| eval risk=case(like(mvjoin(values(action_type)," "),"Audit Log Cleared%"), "CRITICAL", destroy_count > 100, "HIGH", destroy_methods >= 3, "MEDIUM", true(), "LOW")
| table SubjectUserName ComputerName destroy_count destroy_methods targets risk`,

  regulatory_filing_manip: () => `index=saas_finance sourcetype=saas_finance:audit
    action IN ("modify_filing","delete_filing","create_filing","modify_disclosure")
| rex field=document_name "(?i)(sec|ftc|filing|regulatory|10-?[KQ]|8-?K|S-?1|disclosure)"
| stats count as filing_ops
    dc(document_name) as documents
    values(action) as actions
    by user_name source_ip
| where filing_ops > 2
| eval risk=case(filing_ops > 10, "HIGH", "MEDIUM")
| table user_name source_ip filing_ops documents actions risk`,

  digital_stalking: () => `index=calendar sourcetype=calendar
    action IN ("view_calendar","search_calendar","subscribe_calendar","export_calendar")
| stats count as calendar_lookups
    dc(target_user) as colleagues_tracked
    values(target_user) as targets
    by user_name source_ip
| where calendar_lookups > 10 OR colleagues_tracked > 3
| eval risk=case(colleagues_tracked > 10, "HIGH", "MEDIUM")
| table user_name source_ip calendar_lookups colleagues_tracked targets risk

| append [
    index=physical_access sourcetype=physical_access
    action="door_access"
  | stats count as access_events
      dc(door_name) as doors
      values(door_name) as door_list
      by user_name
  | where doors > 10 AND access_events > 50
  | eval tailing=if(doors > 20,"Suspicious Multi-Zone","Elevated")
  | table user_name access_events doors tailing]`,

  threat_comms: () => `index=email sourcetype=email
| rex field=body "(?i)(kill|murder|die|hurt|harm|attack|destroy|ruin|leak|expose|revenge|payback|suffer|threaten|warning.*last.*time)"
| stats count as threat_count
    dc(recipient) as unique_targets
    values(subject) as subjects
    by sender source_ip
| where threat_count > 0
| eval risk=case(threat_count > 5, "CRITICAL", unique_targets > 2, "HIGH", true(), "MEDIUM")
| table sender source_ip threat_count unique_targets subjects risk

| append [
    index=proxy sourcetype=proxy
    (url="*threat*" OR url="*violence*" OR url="*weapon*" OR url="*harm*")
  | stats count as web_ops
      dc(url) as unique_urls
      by cs_username c_ip
  | where web_ops > 3
  | table cs_username c_ip web_ops unique_urls]`,

  unauthorized_surveillance: () => `index=physical_access sourcetype=physical_access
    action="door_access"
    (door_name="*CCTV*" OR door_name="*Security*Room*" OR door_name="*Server*Room*" OR door_name="*NOC*" OR door_name="*Monitoring*")
| stats count as access_count
    dc(door_name) as secure_doors
    values(door_name) as rooms
    by user_name
| where access_count > 3
| eval risk=case(secure_doors > 3, "HIGH", "MEDIUM")
| table user_name access_count secure_doors rooms risk

| append [
    index=crowdstrike sourcetype=crowdstrike:events:ProcessRollup2
    (ImageFileName="*webcam*" OR ImageFileName="*camera*" OR ImageFileName="*obs*" OR CommandLine="*webcam*")
  | stats count as cam_ops
      values(ImageFileName) as tools
      by UserName ComputerName
  | where cam_ops > 5
  | table UserName ComputerName cam_ops tools]`,


};
