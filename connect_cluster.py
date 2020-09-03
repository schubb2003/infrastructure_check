#!/usr/bin/python3
"""
# Author: Scott Chubb scott.chubb@netapp.com
# Written for Python 3.4 and above
# No warranty is offered, use at your own risk.  While these scripts have
#   been tested in lab situations, all use cases cannot be accounted for.
# This script connects to a cluster or node and does some basic error handling
"""

import json
import sys
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def connect_cluster_rest(headers, url, payload):
    """
    Self explanatory - this is how we connect to SolidFire cluster
    Basic error handling for standard connectivity failures
    """
    try:
        response = requests.request("POST",
                                    url,
                                    data=payload,
                                    headers=headers,
                                    verify=False)
        res_code = response.status_code
        res_text = response.text

        if res_code == 200 and '"code":500' not in res_text:
            response_json = json.loads(res_text)
            return response_json
        elif res_code == 401:
            print("Status {}.  Access denied, "
                  "please verify username and "
                  "password".format(res_code))
            sys.exit(1)
        elif response.status_code == 200 and '"code":500' in res_text:
            if "xUnknownUsername" in res_text:
                print("Status {}, but error 500.  LDAP does not "
                      "appear to be configured, "
                      "please verify.  \nThe user has been authenticated "
                      "but not authorized for access".format(res_code))
                sys.exit(1)
            elif "xPermissionDenied" in res_text:
                print("Status {}.  Access denied, "
                      "please verify username and "
                      "password".format(res_code))
            elif "xUnknownAPIMethod" in res_text:
                print("Status {}, but error 500.  Unknown API "
                      "Verify the API call is valid and "
                      "resubmit\nResponse text is: {}".format(res_code,
                                                              res_text))
                sys.exit(1)
            else:
                print("Status {}, but error returned.\n{}"
                      "verify the error and resubmit".format(res_code, res_text))
        elif res_code == 200 and 'null' in res_text:
            print("Status {}, there appears to be an issue with this node. "
                  "This can happen during an upgrade when the node "
                  "responds to pings, but is not serving web traffic. "
                  "Check the node health and try again".format(res_text))
            sys.exit(1)
        else:
            print("Unexpected HTML status in connect cluster module: {}.\n"
                  "Error message:\n{}.\n"
                  "Script will now exit".format(res_code, res_text))

    except Exception as my_except:
        #mvip = url.split("/")[2]
        if "Max retries exceeded" in str(my_except):
            print("Please verify the cluster name is "
                  "{} and retry, host did not respond.".format(url))
            sys.exit(1)
        else:
            print("Unhandled exception:\n{}".format(str(my_except)))

def main():
    """
    Do nothing
    """
    print("This is a module designed to handle connecting to solidfire clusters, exiting.")

if __name__ == "__main__":
    main()
