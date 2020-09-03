#!/usr/bin/python
"""
# Author: Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have
#   been tested in lab situations, all use cases cannot be accounted for.
"""

import base64
import json
import requests
from connect_cluster import connect_cluster_rest as connect_cluster


def build_auth(mvip, user, user_pass, mvip_node=None):
    """
    Authorization for connecting to the cluster mvip on port 443
    """
    if mvip_node is None:
        mvip_node = "cluster"
    token_url = "https://" + mvip + "/auth/connect/token"
    m_url = "https://" + mvip + "/json-rpc/"
    n_url = "https://" + mvip + ":442/json-rpc/"

    files = {
        'client_id': (None, 'element-automation'),
        'grant_type': (None, 'password'),
        'username': (None, user),
        'password': (None, user_pass),
    }

    response = requests.post(url=token_url, files=files, verify=False)
    res_code = response.status_code
    if res_code is 200:
        print("Using token authentication")
        token_json = json.loads(response.text)
        token_out = token_json['access_token']
        auth_bear = "Bearer " + token_out
        headers = {'Authorization': auth_bear}

    else:
        print("Using basic auth without token grant")
        auth = (user + ":" + user_pass)
        encode_key = base64.b64encode(auth.encode('utf-8'))
        basic_auth = bytes.decode(encode_key)

        headers = {
            'Content-Type': "application/json",
            'Authorization': "Basic %s" % basic_auth,
            'Cache-Control': "no-cache",
            }

    if mvip_node == "cluster":
        url = m_url + "9.0"
    else:
        url = n_url + "9.0"

    payload = build_payload()
    response_json = connect_cluster(headers, url, payload)
    # Return the latest API supported and provide that output to
    #   connect_cluster module
    latest_api = get_version(response_json)
    if mvip_node == "cluster":
        url = m_url + latest_api
    else:
        url = n_url + latest_api
    return headers, url


def build_payload():
    """
    This is where we build the payload to get the API return from the system
    """
    payload = json.dumps({"method": "GetAPI", "params":{}, "id": 1})
    return payload


def get_version(response_json):
    """
    This gets the highest API level the cluster will support
      and returns it so that we connect to the latest available API version
    """
    support_api = (response_json['result']['supportedVersions'])
    latest_api = support_api[-1]
    return latest_api


def main():
    """
    Nothing happens here
    """
    print("This is a module designed to handle building "
          "auth credentials to solidfire clusters, exiting.")


if __name__ == "__main__":
    main()
