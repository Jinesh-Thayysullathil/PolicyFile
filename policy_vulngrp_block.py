import requests,json,sys,ssl,certifi,urllib,subprocess,config,re
import urllib
from requests.auth import HTTPBasicAuth
from collections import ChainMap
iq_server = config.iq_server
api = config.api
api_vg = config.api_vg
username = config.username
password = config.password
headers = config.headers
csrf_url = config.csrf_url
#certs = config.certs
commit_id_long = config.commit_id
commit_id = commit_id_long[0:7]
file_name_cso_block = "CSO-BLOCK-LIST-TST" + ".txt"
file1 = open(file_name_cso_block, "w" )

print('\n##### Executing the script for Block #####')

print('\nLatest Short Commit ID is ',commit_id)

### -------- Script for Vulnerabilty Group ------------###

# Appending Latest Commit ID to the Must Fix List for vuln_group_name

vuln_group_name = 'Must Fix List Block'+' - '+commit_id

# Update and Create could be merged into a single add_update method
def update_vuln_group(owner_id, vuln_group_name):
    url = f"{iq_server}/{api_vg}/vulnerability/group/organization/{owner_id}"
    print('\nurl in python script ',url)
    body = {
        "vulnerabilityGroupId": retrieve_vuln_group_id(owner_id, vuln_group_name),
        "groupName": vuln_group_name, 
        "vulnerabilityIds": parse_cves_from_json(cso_mfl_file='MFL_CVE.json'), 
        "ownerId": owner_id
    }
 #   print ('Vulnerebility id is \n',vulnerabilityIds)
    vuln_group_response = requests.post(
        # url, headers=headers, verify=certs, json=body
        url, headers=headers,json=body
    )
    return vuln_group_response



def retrieve_vuln_group_id(owner_id, vuln_group_name):
    url = f"{iq_server}/{api_vg}/vulnerability/group/organization/{owner_id}/name/{vuln_group_name}"
    print ('URL is this \n', url)

    vuln_group_response = requests.get(
#   url, headers=headers, verify=certs
    url, headers=headers
    )
    print('\nvuln_group_response status code is ',vuln_group_response.status_code)
    print('\nvuln_group_response text code is ',vuln_group_response.text)
    
        # Return Vuln. Group ID if the Vuln. Group exists
    if (vuln_group_response.status_code) != 200:
        create_vuln_group(owner_id, vuln_group_name)
    else:
        vuln_group_response = json.loads(vuln_group_response.text)
        return vuln_group_response['vulnerabilityGroupId']



def create_vuln_group(owner_id, vuln_group_name):
    url = f"{iq_server}/{api_vg}/vulnerability/group/organization/{owner_id}"
    body = {
        "groupName": vuln_group_name,
        "vulnerabilityIds": parse_cves_from_json(cso_mfl_file='MFL_CVE.json'), 
        "ownerId": owner_id
    }

    vuln_group_response = requests.post(
        # url, headers=headers, verify=certs, json=body
        url, headers=headers, json=body
    )
    return vuln_group_response

# Extracts an array of CVE IDs from the given file
#  e.g. ["CVE1", "CVE2"]
def parse_cves_from_json(cso_mfl_file):
    cves = []
    with open(cso_mfl_file) as json_file:
        data = json.load(json_file)
        data_array = (data['must_fix_list'])
        # print(("\nMust fix list arary", data_array))
        key= 'detection_context'
        value='deployment_pipeline'
        # Extract the value of the action_defaults key value
        for d in data['action_defaults']:
            if d.get(key) == value:
                DEFAULT_action_default = f"{d.get('action')}"
                break
        else:
            print("No matching record found")
        # print("\nDEFAULT_action_default key value is ",DEFAULT_action_default)
        # Check if Key named 'action' present in the nested list of dictionaries. 
        for obj in data['must_fix_list']:
            found = False
            key = 'action'
            # If key named 'action' present in the list of ['affected_components'] then check for the 'action' value and perform the action
            for act in obj['affected_components']:
                if key in act :
                    found = True
                    for act in obj['affected_components']:
                        action_val = act.get('action')
                        if action_val == 'block':
                            # print(obj['identifier'])
                            # Most elements are individual strings (good)
                            if isinstance(obj['identifier'], str):   
                                # print (obj['identifier'])
                                if 'CVE' in obj['identifier'] or 'sonatype' in obj['identifier']:
                                    cves.append(obj['identifier'])
                                    file1.writelines(obj['identifier'])
                                    file1.writelines('\n')
                            # Some elements are arrays (unfortunate)
                            else:
                                for item in obj['identifier']:
                                    if 'CVE' in item or 'sonatype' in item or 'GHSA' in item:
                                        cves.append(item)
                                        file1.writelines(item)
                                        file1.writelines('\n')
                    break
            # If key named 'action' not present in the list of ['affected_components'] then check the value of DEFAULT_action_default and perform the action
            if not found: 
                if DEFAULT_action_default == 'block':
                    if isinstance(obj['identifier'], str):   
                        # print (obj['identifier'])      
                        if 'CVE' in obj['identifier'] or 'sonatype' in obj['identifier']:
                            cves.append(obj['identifier'])
                            file1.writelines(obj['identifier'])
                            file1.writelines('\n')
                            # Some elements are arrays (unfortunate)
                    else:
                        for item in obj['identifier']:
                            if 'CVE' in item or 'sonatype' in item or 'GHSA' in item:
                                cves.append(item)
                                file1.writelines(item)
                                file1.writelines('\n')
    return cves

def print_vuln_group_id(owner_id, vuln_group_name):
    url = f"{iq_server}/{api_vg}/vulnerability/group/organization/{owner_id}/name/{vuln_group_name}"
    vuln_group_response = requests.get(
        # url, headers=headers, verify=certs
        url, headers=headers
    )
    print('\nvuln_group_cve_ids related to Block/Fail is ',vuln_group_response.text)

vulnerabilityGroupId_value = (update_vuln_group('ROOT_ORGANIZATION_ID', vuln_group_name).text)
# vgID_str=str(vulnerabilityGroupId_value)
# print('\nvulnerabilityGroupId_value is',vgID_str)
#vulnerabilityGroupId_value = (update_vuln_group('ROOT_ORGANIZATION_ID', vuln_group_name).text)

print_vuln_group_cve_ids = (print_vuln_group_id('ROOT_ORGANIZATION_ID', vuln_group_name))

vgID_str=str(vulnerabilityGroupId_value)

print('\nvulnerabilityGroupId_value is',vgID_str)

### -----------Script for Policy--------------------- ###

def return_policy_id(owner_id, policy_name):
    url = f"{iq_server}/{api}/policy/organization/{owner_id}"
    policy_response = requests.get(
    # url, headers=headers, verify=certs
    url, headers=headers
    )
    print(policy_response)
    for policy in json.loads(policy_response.text):
        if policy['name'] == policy_name:
            return policy['id']
    return False

def create_update_policy(owner_id, policy_json):
    policy_id = return_policy_id(owner_id, policy_json['name'])
    url = f"{iq_server}/{api}/policy/organization/{owner_id}"
    csrf_url = config.csrf_url
    print('\nHeaders in the Dictionary List -',headers)
  
    if policy_id:
        policy_response = requests.put(
            # url, headers=headers, verify=certs, json=policy_json
        url, headers=headers,json=policy_json

        )
        return policy_response
    else:
        policy_response = requests.put(
            # url, headers=headers, verify=certs, json=policy_json
        url, headers=headers,json=policy_json
        )
        return policy_response

json_policy_template = """{
                            "id": "must_fix_list_block",
                            "name": "MustFix_BLOCK_%s",
                            "ownerId": "ROOT_ORGANIZATION_ID",
                            "threatLevel": 10,
                            "policyViolationGrandfatheringAllowed": false,
                            "policyActionsOverrideAllowed": null,
                            "constraints": [
                                {
                                    "name": "Must Fix List Block (%s)",
                                    "conditions": [
                                        {
                                            "conditionTypeId": "VulnerabilityGroup",
                                            "operator": "is",
                                            "value": "%s"
                                        }
                                    ],
                                    "operator": "AND"
                                }
                            ],
                            "actions": {
                                "proxy": "fail",
                                "develop": "fail",
                                "source": "fail",
                                "build": "fail",
                                "stage-release": "fail",
                                "release": "fail",
                                "operate": "fail"
                            },
                            "notifications": {
                                "userNotifications": [],
                                "roleNotifications": [],
                                "jiraNotifications": [],
                                "webhookNotifications": []
                                }
                        }""" %(commit_id,commit_id,vgID_str)


#print(create_update_policy('ROOT_ORGANIZATION_ID', json.loads(json_policy_template)).text)
policy_status = (create_update_policy('ROOT_ORGANIZATION_ID', json.loads(json_policy_template)).status_code)
print("\nPolicy Creation Status Code is", policy_status)
url = f"{iq_server}/{api}/policy/organization/ROOT_ORGANIZATION_ID/"
policy_json = json.loads(json_policy_template)


if policy_status == 404:
    policy_response = requests.post(
        url, headers=headers,json=policy_json
        # url, headers=headers, verify=certs, json=policy_json
        )
    print('\nPolicy ID is new and created')
if policy_status == 200:
    print('\nPolicy ID Exists & Updated')
else:
    print('\nNo vulnerabilities provided in the request and hence the policy is neither created nor updated')

file1.close()