#MASTER CONFIG FILE FOR PASSING USER INPUTS#
import requests,subprocess,re,os,urllib
from base64 import b64encode

username = 'admin'
password = 'iOnYMnEWARiBROnE'
commit_id = 'test'
iq_server = 'https://nexusiq.mgmt-tst.oncp.dev'
# env = os.environ['inspect_iqpolicyupdate_vault']

csrf_url_link = '/assets/index.html'
csrf_url = iq_server + csrf_url_link

repo_url = 'https://ghe.service.group/cso-sit/MFLs'
api = 'rest'
api_vg = 'api/experimental'
# certs = '/app/ca-certificates.crt'
response = requests.get(
    csrf_url,auth=(username, password)
    # csrf_url,auth=(username, password), verify=certs
)
def basic_auth(username, password):
    token = b64encode(f"{username}:{password}".encode('utf-8')).decode("ascii")
    return f'Basic {token}'
headers = {"Content-Type": "application/json"}
headers = { 'Authorization' : basic_auth(username, password) }
headers['x-csrf-token'] = '; '.join([x.value for x in response.cookies])
headers['cookie'] = '; '.join([x.name + '=' + x.value for x in response.cookies])