import argparse
import requests
import json
from collections import OrderedDict
import os
import datetime
import subprocess
from subprocess import check_output
import re
import logging
import sys
import traceback

requests.packages.urllib3.disable_warnings()

# Logging
#Log levels
_MESSAGE = 0
_INFO = 1
_DEBUG = 2
_EXTRA = 3
_WARNING = -2
_ERROR = -1
_DEBUG_LEVEL = 2

_DEBUG_CONF_LEVEL = {
    "DEBUG": _DEBUG,
    "EXTRA": _EXTRA,
    "NORMAL": _INFO
}

_LOGGER = None

_MESSAGE_TEXT = {
    _MESSAGE: "",
    _INFO: "INFO: ",
    _ERROR: "ERROR: ",
    _EXTRA: "DEBUG: ",
    _DEBUG: "DEBUG: ",
    _WARNING: "WARNING: "
}

_REQUEST_TIMEOUT = 600

def debug (msg, level = _MESSAGE, json_flag = False):

    global _LOGGER

    if level <= _DEBUG_LEVEL :
        if json_flag:
            log_msg = json.dumps(msg, indent=4, separators=(',', ': '))
            print(log_msg)
            if _LOGGER:
                _LOGGER.info(log_msg)
        else:
            print(_MESSAGE_TEXT[level]+str(msg))
            if _LOGGER:
                _LOGGER.info(_MESSAGE_TEXT[level]+str(msg))
    return None


def get_date_timestamp(current_time=False):
    """
    :param date_format:
        if True returns only YYYY_MM_DD format
        if False returns YYYY_MM_DD_HH_MI_SS format
    :return:
    """
    if not current_time:
        return datetime.datetime.now().strftime('_%Y_%m_%d_%H_%M_%S')
    else:
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# SFDC API URIs
SFDC_API = {
            "GET_TOKEN":("/services/oauth2/token", requests.post),
            "GET_VERSIONS":("", requests.get),
            "DESCRIBE_OBJECT":("sobjects/{}/describe", requests.get)
           }

# Function processes properties json file
def get_json_file(in_json_file):
    """ Args:
                    in_json_file - fileobject returned by argparse
        Returns:
                    dictionary of properties defined in passed properties file
        Raises:
            json.decoder.JSONDecodeError: if config file is not valid JSON document
    """
    try:
        out_json_properties = json.load(in_json_file, encoding='utf-8', object_pairs_hook=OrderedDict)
        return out_json_properties
    except json.decoder.JSONDecodeError as json_err:
        debug("Provided config file {} is not valid JSON document".format(in_json_file), _ERROR)
        debug(json_err, _ERROR)
        exit(1)
# ************************************

def get_etl_properties(in_file=None):

    if in_file is None:
        in_file_name = "informatica.properties"
    else:
        in_file_name = in_file

    etl_properties = dict()
    if os.path.isfile(in_file_name):
        try:
            etl_properties_fh = open(in_file_name)
            for line in etl_properties_fh:
                if line == "\n": continue
                line = line.strip()
                line_tokens = line.split('=')
                etl_properties[line_tokens[0]] =line_tokens[1]

            return etl_properties

        except IOError as e:
            debug("Cannot open file: {}".format(in_file), _WARNING)
            debug("Error: {}".format(str(e)), _ERROR)
    else:
        debug("File {} does not exist".format(in_file_name), _DEBUG)
        # return empty dict to avoid failures, it is ok
        return etl_properties

def get_sfdc_api_url(app_properties, api_uri, *params, in_current_instance=None, in_api_version=None):
    """
    :param client_properties:
    :param api_uri: API request, like login, connections.
    :return:
    """
    debug("Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    if in_current_instance is None:
        resource_uri = app_properties["sfdc_login_uri"]
    else:
        resource_uri = in_current_instance



    root_uri = app_properties["root_uri"]
    if api_uri == "GET_TOKEN":
        api_request = resource_uri + SFDC_API[api_uri][0]
    elif api_uri == "GET_VERSIONS":
        api_request = resource_uri + root_uri + SFDC_API[api_uri][0]
    else:
        if in_api_version is None:
            debug("SFDC API version is required", _ERROR)
        else:
            version_root = in_api_version["url"]
            api_request = resource_uri + version_root + '/' + SFDC_API[api_uri][0]

    if params:
        api_request = api_request.format(*params)

    debug("Constructed API URL: {}".format(api_request))
    return api_request

def run_restapi(in_token, in_instance_url, in_uri):
    """Args:

    """
    url = in_instance_url + in_uri
    r = requests.get(url, headers={"Authorization": "Bearer " + in_token});
    response_json = r.json()
    return response_json

# Complete function - constructs and runs defined API call
def  run_sfdc_restapi(app_properties, in_access_token,
                      api_call_name,
                      *api_params,
                      in_payload=None,
                      in_current_instance_url=None,
                      in_api_version=None):
    """
    :param client_properties:
    :param in_access_token:
    :param api_call_name:
    :param api_params: optional
    :param in_payload:
    :return: raw response
    """
    debug("Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    #debug("Current Token: {}".format(in_access_token), _DEBUG)
    #debug("Current Instance URL: {}".format(in_current_instance_url), _DEBUG)

    header_content = {"Authorization": "Bearer " + in_access_token}

    if in_current_instance_url is None:
        api_url = get_sfdc_api_url(app_properties, api_call_name, *api_params)
    else:
        if in_api_version is None:
            api_url = get_sfdc_api_url(app_properties, api_call_name, *api_params, in_current_instance=in_current_instance_url)
        else:
            api_url = get_sfdc_api_url(app_properties, api_call_name, *api_params,
                                       in_current_instance=in_current_instance_url,
                                       in_api_version=in_api_version)


    if in_payload == None:
        r = SFDC_API[api_call_name][1](api_url, headers=header_content, verify=False, timeout=_REQUEST_TIMEOUT)
    else:
        r = SFDC_API[api_call_name][1](api_url, headers=header_content, data = in_payload, verify=False,  timeout=_REQUEST_TIMEOUT)

    return r

def sfdc_get_token(app_properties):
    """
    :param app_properties:
    :return:
    """
    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    debug("Obtaining Salesforce access token and instance url", _INFO)

    header = {"Content-Type": "application/x-www-form-urlencoded"}
    payload = { 'grant_type': 'password', \
                'client_id': app_properties["consumer_key"], \
                'client_secret': app_properties["consumer_secret"], \
                'username': app_properties["username"], \
                'password': app_properties["password"]
              }
    # Construct uri to obtain security token
    token_uri = get_sfdc_api_url(app_properties, "GET_TOKEN")
    r_token = SFDC_API["GET_TOKEN"][1](token_uri, headers=header, data=payload)

    body = r_token.json()
    debug("Response body: {}".format(body))
    response_status = body.keys()
    debug("Response status {}".format(response_status))

    # Response handling
    if 'error' in body.keys():
        debug("Cannot authenticate user. Reason: {} Description: {}".format(body["error"], body["error_description"]), _ERROR)
        debug("Application execution will be terminated", _ERROR)
        exit(1)
    else:
        token = body["access_token"]
        debug("Successfully obtained security token. Access token {}".format(token), _INFO)

        instance_url = body["instance_url"]
        debug("Current Instance URL: {}".format(instance_url), _INFO)
        return body
# Obtain API endpoint versions
def sfdc_get_versions(app_properties, in_current_token, in_current_instance_url):
    """
    :param app_properties:
    :param in_current_token:
    :param in_current_instance_url:
    :return: Lists summary info about each Salesforce version currently available,
             including verison, label and link to each versio root.
    """
    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)
    expected_sfdc_api_version = app_properties["sfdc_api_version"]

    # versions_uri = "/services/data/"
    # versions_uri = get_sfdc_api_url(app_properties, "GET_VERSIONS", in_current_instance=in_current_instance_url)
    # r = requests.get(versions_uri, headers=header_content);

    r = run_sfdc_restapi(app_properties, in_current_token, "GET_VERSIONS", in_current_instance_url=in_current_instance_url)
    body = r.json()

    for li in body:
        debug("Available SFDC REST API versions: {}".format(li))

    for li in body:
        # debug("Available SFDC REST API versions: {}".format(li))
        #debug("Version : {}".format(li["version"].replace(' \'', '')))
        current_sfdc_api_version = li["version"]
        if expected_sfdc_api_version != current_sfdc_api_version: continue
        debug("Using SFDC API version: {}".format(li))
        #debug("SFDC REST API version info type: {}".format(type(current_sfdc_api_version)))
        current_sfdc_api_root = li
        return current_sfdc_api_root


def sfdc_describe_object(app_properties, in_current_token, in_object, in_current_instance_url, in_current_api_version):
    """
    :param app_properties:
    :param in_current_token:
    :param in_object:
    :param in_current_instance_url:
    :param in_current_api_version:
    :return:
    """
    debug("********************************************************************************")
    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    r_desc = run_sfdc_restapi(app_properties,
                              in_current_token,
                              "DESCRIBE_OBJECT",
                              in_object,
                              in_current_instance_url=in_current_instance_url,
                              in_api_version=in_current_api_version)
    object_desc_body = r_desc.json()
    #debug("Object Desc Body type: {}".format(type(object_desc_body)))

    sfdc_object_metadata = list()
    # Salesforce returns response body as dict if success and as a list if error.
    # need to check what object type is response body.
    if isinstance(object_desc_body, (dict)):
        debug("SFDC Object metadata: {}".format(in_object), _DEBUG)

        for dictIter in object_desc_body["fields"]:
            attr_name = dictIter["name"]

            attr_datatype = dictIter["type"]
            # different attributes contain data precision values depending on datatype
            # Percent - 'precision', 'scale'
            # Reference - byteLength or length
            # Boolean - Infa Precision=10, SFDC=0. set SFDC to 10
            # String - 'length'
            # Picklist -
            attr_precision = str(dictIter["precision"])
            attr_length = str(dictIter["length"])
            att_byteLength = str(dictIter["byteLength"])
            attr_scale = str(dictIter["scale"])

            #line = "NAME:" + attr_name + ", DATATYPE:" + attr_datatype + ", PRECISION:" + attr_precision + ", SCALE:"+ attr_scale
            #line = "NAME:" + attr_name
            sfdc_object_metadata.append(attr_name)
            #debug(line)

        debug(sfdc_object_metadata)
        return sfdc_object_metadata

    elif isinstance(object_desc_body, (list)):
        debug(object_desc_body)
        object_desc_body_err = object_desc_body[0]
        if 'errorCode' in object_desc_body_err.keys():
            debug("Cannot extract Object {} metadata".format(in_object), _ERROR)
            debug("Reason: {}".format(object_desc_body_err["message"]), _ERROR)
            #exit(1)

    else:
        debug("Unsupported response body type", _ERROR)
        exit(1)

    debug("********************************************************************************")

    # for dictIter in obj_desc["fields"]:
    # 	debug("Attribute: name:{} type:{} precision:{} scale:{}".format(dictIter["name"], dictIter["type"], dictIter["precision"], dictIter["scale"]), _DEBUG)


# def sfdc_get_access_token_instance(app_properties):
#
#     debug("Obtaining Salesforce access token and instance url", _INFO)
#
#     sfdc_login_uri = "https://login.salesforce.com/"
#     token_uri =  sfdc_login_uri + "services/oauth2/token"
#     debug("Token URI: {}".format(token_uri), _DEBUG)
#
#     header = {"Content-Type":"application/x-www-form-urlencoded"}
#
#     payload = {'grant_type': 'password', \
#                 'client_id': app_properties["consumer_key"], \
#                 'client_secret': app_properties["consumer_secret"], \
#                 'username': app_properties["username"], \
#                 'password': app_properties["password"]
#           }
#     r = requests.post(token_uri, headers=header, data=payload)
#
#     # Convert stream of bytes into json formatted list
#     body = r.json()
#     debug("Response body: {}".format(body))
#     response_status = body.keys()
#     debug("Response status {}".format(response_status))
#
#     # Response handling
#     if 'error' in body.keys():
#         debug("Cannot authenticate user. Reason: {} Description: {}".format(body["error"], body["error_description"]), _ERROR)
#         debug("Application execution will be terminated", _ERROR)
#         debug("Need to exit, but will continue with development for now. Remove this in complete version", _ERROR)
#         #exit(1)
#     else:
#         token = body["access_token"]
#         debug("Access token {}".format(token), _INFO)
#
#         instance_url = body["instance_url"]
#         debug("Instance URL: {}".format(instance_url), _INFO)
#         return body

    # # *************** get token and url ******************************
    # # Define SFDC REST API URI
    # sfdc_login_uri = "https://login.salesforce.com/"
    # token_uri=  sfdc_login_uri + "services/oauth2/token"
    # #token_uri = "https://login.salesforce.com/services/oauth2/token"
    #
    # # TBD - Check User-agent flow, used by applications that cannot securely store the consumer secret.
    #
    # # Connect to Salesforce org and obtain token and instance url info for subsequent API calls
    # # Construct payload
    # payload = {'grant_type': 'password',
    #            'client_id': app_properties["consumer_key"],
    #            'client_secret': app_properties["consumer_secret"],
    #            'username': app_properties["username"],
    #            'password': app_properties["password"]
    #           }
    # # Construct request for token. This is the first step in establishing connection to SFDC
    # # Token received is used by all consequtive REST API calls
    #
    # r = requests.post(token_uri, headers={"Content-Type":"application/x-www-form-urlencoded"}, data=payload)
    # # Convert stream of bytes into json formatted list
    # body = r.json()
    # token = body["access_token"]
    # debug("Access token {}".format(token), _INFO)
    # instance_url = body["instance_url"]
    # debug("Instance URL: {}".format(instance_url), _INFO)
    # #*************** end of getting token and url ******************************

def get_files(directory, fpath = False):
    """
    Args:
        directory - starting directory to list files
        fpath - flag indicates whether to return file path and name or just name
            False - returns only filename
            True  - returns fully qualified filename: path/filename
        Function generates the file names in a directory
        tree by walking the tree either top-down or bottom-up. For each
        directory in the tree rooted at directory top (including top itself),
        it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List stores filenames with or without path.

    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            if fpath:
                # Join the two strings in order to form the full filepath.
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)
            else:
                file_paths.append(filename)

    return file_paths

def get_infa_files(app_properties, infa_export_dir):
    """
    :param app_properties:
    :param infa_export_dir:
    :return:
    """
    debug("Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    #object_type_process = app_properties.get("infa_object_type")
    source_dbd_names = app_properties.get("infa_src_dbdnames")
    targets = app_properties.get("infa_tgt")

    infa_all_files = get_files(infa_export_dir, fpath=False)
    _include_xml_files = [fn for fn in infa_all_files if fn.endswith('XML')]

    # filter out tokenized files generated by InformaticaIntegration exportdeployment action
    _infa_xml_files = [fn for fn in _include_xml_files if not fn.startswith('ETL_')]

    if source_dbd_names is None:
        if targets is None:
            infa_xml_files = [os.path.join(infa_export_dir, fn) for fn in _infa_xml_files]
            infa_xml_files.sort()

    #debug("Files for processing:\n{}".format('\n'.join(_infa_xml_files)), _DEBUG)

    # infa_xml_files = list()
    # # Select source files according to defined source db
    # for fi in _infa_xml_files:
    #     for srcdb in source_dbd_names:
    #         #debug("Matching file: {} with source db name: {}".format(fi, srcdb), _DEBUG)
    #         if fi.startswith(srcdb):
    #             file_name = os.path.join(infa_export_dir, fi)
    #             infa_xml_files.append(file_name)
    # # Select target files according to defined targets
    # for fi in _infa_xml_files:
    #     for tgt in targets:
    #         match_tgt = re.compile('^({0})'.format(tgt))
    #         if match_tgt.match(fi):
    #             file_name = os.path.join(infa_export_dir, fi)
    #             infa_xml_files.append(file_name)


    # match_model = re.compile('^(c_|base_)\S+(_model_{0})'.format(ClientID))
    debug("Files to be processed:\n{}".format('\n'.join(infa_xml_files)), _DEBUG)
    return infa_xml_files

# def infa_connect(app_properties):
#     """
#     :param app_properties:
#     :return:
#      Function establishes connection to Informatica
#     """
#     debug("**********************************************************************")
#     debug("     Connecting to Informatica", _INFO)
#
#     repository_name = app_properties["infa_repository_name"]
#     host = app_properties["infa_host"]
#     port = app_properties["infa_portal_port"]
#     user_name = app_properties["infa_user_name"]
#     user_passwd = app_properties["infa_user_password"]
#
#     # pmrep connect -r rep_sf1impd1 -h sf1impd1 -o 7006 -n Administrator -x Administrator
#     command_str = "pmrep connect -r "+repository_name+" -h "+host+" -o "+port+" -n "+user_name+" -x "+user_passwd
#     command = command_str.split()
#     debug("Executing Informatica API: {}".format(command_str), _INFO)
#     #subprocess.run(command.split(), timeout=60)
#     _command_output = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, ).communicate()
#     command_output = str(_command_output[0]).split('\n')
#
#     infa_cmd_status(command_str, command_output)
#     debug("**********************************************************************")

# def infa_listobjects(app_properties):
#     """
#     :param app_properties:
#     :return:
#      Function establishes connection to Informatica
#     """
#     debug("**********************************************************************")
#     debug("     Getting list of objects", _INFO)
#
#     object_type = app_properties["infa_object_type"]
#     folder_name = app_properties["infa_client_folder"]
#     source_dbdnames = app_properties["infa_src_dbdnames"]
#     target_names = app_properties["infa_tgt"]
#
#     # # Cleanup before processing - remove listobjects.txt if it exists
#     # try:
#     #     os.remove('listobjects_out.txt')
#     #     debug("File listobjects_out.txt was removed", _INFO)
#     # except OSError:
#     #     debug("Cannot remove file listobjects_out.txt", _ERROR)
#
#     object_list = list()
#
#     # Go through object types and execute Informatica listobject command for each object type
#     for object_type_iter in object_type:
#         debug("Processing Object Type: {}".format(object_type_iter), _INFO)
#         command_str = "pmrep listobjects -f "+ folder_name + " -o " + object_type_iter
#         command = command_str.split()
#         debug("Executing Informatica API: {}".format(command_str), _INFO)
#
#         #out = check_output(["ntpq", "-p"])
#         _out = check_output(command)
#         out = _out.decode('utf8').split('\n')
#         #debug("Raw output list: {}".format(out), _DEBUG)
#         debug("Process raw output to store what is needed based on configuration", _INFO)
#         for out_iter in out:
#             if re.search('^({0})'.format(object_type_iter), out_iter):
#                 if object_type_iter == 'source':
#                     for src_dbname_iter in source_dbdnames:
#                         if re.search('^source ({0}[.])'.format(src_dbname_iter), out_iter):
#                             object_list.append(out_iter)
#                 elif object_type_iter == 'target':
#                     for tgt_name_iter in target_names:
#                         if re.search('^target ({0})'.format(tgt_name_iter), out_iter):
#                             object_list.append(out_iter)
#
#         # # Store process output in file listobjects.txt
#         # debug("Open listobjects_out.txt file to store command output", _DEBUG)
#         # with open("listobjects_out.txt", "a") as fh:
#         #     execute_command = subprocess.Popen(command, stdout=fh, stderr=fh, ).communicate()
#
#         #proc = subprocess.Popen(command, stdout=subprocess.PIPE)
#         #execute_command = proc.communicate()
#         #debug("Raw listobjects result: '\n'".format(eval(execute_command.decode('utf-8').split('\n')[0])), _DEBUG)
#
#         # if infa_cmd_status(command_str, execute_command):
#         #     debug("Successfully created a list of Objects type: {}".format(object_type_iter), _INFO)
#         # else:
#         #     debug("Failed to execute command: {}".format(command_str), _DEBUG)
#         # debug("Test infa_cmd_execute", _DEBUG)
#         # myoutput = infa_cmd_execute(command)
#         # debug("My output: '\n'".format(myoutput), _DEBUG)
#
#         # with open("listobjects_out.txt", "r") as fh:
#         #     command_output = list(fh)
#
#         if infa_cmd_status(command_str, out):
#             debug("Successfully created a list of Object Type: {}".format(object_type_iter), _INFO)
#         else:
#             debug("Failed to create a list of Object Type: {}".format(object_type_iter), _ERROR)
#             exit(1)
#
#     debug("**********************************************************************")
#     return object_list

def infa_export(app_properties, objects_list, infa_export_dir):
    """
    :param app_properties:
    :param objects_list:
    :return:
    """
    debug("Function call - {}".format(sys._getframe().f_code.co_name), _INFO)
    # pmrep objectexport  -m -s -b -r  -o {3} -f {0} -u {1} -n {2}
    # pmrep objectexport - m - s - b - r - o source - f GPMWINTER2018 - u REVVY.MnInstallBase__c.XML - n REVVY.MnInstallBase__c
    # Will utilize InformaticaIntegration app
    object_type = app_properties["infa_object_type"]

    os.chdir(infa_export_dir)
    for obj_type in object_type:
        command_str = "java -jar ../Scripts/InformaticaIntegration.jar exportdeployment None "+obj_type
        command_exp = command_str.split()
        debug("Executing Informatica API: {}".format(command_str), _INFO)

        exec_export_out = infa_cmd_execute(command_exp)

        # _out = check_output(command_exp)
        # out = _out.decode('utf8').split('\n')

        debug("Command output:\n{}".format(exec_export_out), _DEBUG)

        if infa_cmd_status(command_str, exec_export_out):
            debug("Successfully run export for Object Type: {}".format(obj_type), _INFO)
        else:
            debug("Failed to run Object Type {} export".format(obj_type), _ERROR)
            exit(1)

        # Backup ../Logs/exportdeployment.log for each Object Type exported
        try:
            os.rename("../Logs/exportdeployment.log", "../Logs/exportdeployment_{}_{}.log".format(obj_type, get_date_timestamp()))
        except OSError as e:
            debug("Cannot rename file exportdeployment log file", _ERROR)


def infa_cmd_execute(command):
    """
    Execute an external command and return its output as a list where
    each list element corresponds to one STDOUT line returned by the
    command.
    Args: command (list): OS command call formatted for the subprocess'
    Returns: output text as a List
    """
    debug("Function call - {}".format(sys._getframe().f_code.co_name), _INFO)
    from subprocess import check_output
    #import subprocess  # import only on demand
    # command_output = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, ).communicate()
    _out = check_output(command)
    out = _out.decode('utf8').split('\n')
    return out
    #return command_output[0].split('\n')

def infa_cmd_status(command, command_output):
    """
    Check if the command has been successfully executed.

    A command is considered be executed successfully if the output
    stream contains a string 'completed successfully'.
    Args:
        command (list): executed command
        command_output(list): output of that command

    Returns: raises Exception or True
    """
    if not any('completed successfully' in line for line in command_output):
        debug("\n".join(command_output), _INFO)
        raise Exception("failed to execute: %s" % " ".join(command))
    else:
        debug("Informatica command: \n {} completed successfully".format(command), _INFO)
        return True

def infa_parse_xml(app_properties, xml_files, infa_metadata_dir):
    """
    :param app_properties:
    :return:
    """
    import xml.etree.ElementTree as ET

    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    parse_tags = ['SOURCEFIELD', 'TARGETFIELD']
    # iterate through list of files and parse XML to extract metadata for sources and targets :
    #   column name, datatype, data precision and scale
    for fn in xml_files:
        file_name = os.path.basename(fn)
        infa_metadata_file = os.path.join(infa_metadata_dir, file_name)
        debug("Processing Informatica XML file: {}".format(file_name))

        if fn.endswith('MnIRP__Exchange_Rate__c.XML') or fn.endswith('EtlRunInfo__c.XML'):
            debug("Parsing file: {}".format(fn), _INFO)
            tree = ET.parse(fn)
            root = tree.getroot()
            for childattr in root[0][0][0]:
                if childattr.tag not in parse_tags: continue

                attr_name = childattr.get('NAME')
                attr_datatype = childattr.get('DATATYPE')
                attr_precision = childattr.get('PRECISION')
                attr_scale = childattr.get('SCALE')
                line = "NAME:"+attr_name+", DATATYPE:"+attr_datatype+", PRECISION:"+attr_precision+", SCALE:"+attr_scale
                #debug("NAME: {}, DATATYPE: {}, PRECISION: {}, SCALE: {}".format(attr_name, attr_datatype, attr_precision, attr_scale))
                debug("Line to write into file: {}\n{}".format(file_name, line), _DEBUG)

                # # need to identify if the file is Source or Target
                # for tagattr in root.iter('SOURCEFIELD'):
                #     #debug("Iterate over SOURCEFIELD: {}".format(tagattr.attrib), _DEBUG)
                #     attr_name = tagattr.get('NAME')
                #     attr_datatype = tagattr.get('DATATYPE')
                #     attr_precision = tagattr.get('PRECISION')
                #     attr_scale = tagattr.get('SCALE')
                #     line = "NAME:" + attr_name + ", DATATYPE:" + attr_datatype + ", PRECISION:" + attr_precision + ", SCALE:" + attr_scale
                #     debug("NAME: {}, DATATYPE: {}, PRECISION: {}, SCALE: {}".format(attr_name, attr_datatype, attr_precision, attr_scale))

                # Write object metadata if needed
                with open(infa_metadata_file, 'w') as fh:
                    fh.write(line+'\n')

def infa_describe_all_objects(xml_files):

    import xml.etree.ElementTree as ET

    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    parse_tags = ['SOURCEFIELD', 'TARGETFIELD']
    # iterate through list of files and parse XML to extract metadata for sources and targets :
    #   column name, datatype, data precision and scale
    for fn in xml_files:

        file_name = os.path.basename(fn)
        #infa_metadata_file = os.path.join(infa_metadata_dir, file_name)
        debug("Processing Informatica XML file: {}".format(file_name))

    # Remove IF statement and correct indent before use.
       # if fn.endswith('MnIRP__Exchange_Rate__c.XML'): # or fn.endswith('EtlRunInfo__c.XML'):
        if fn.endswith('REVVY__MnContract__c.XML'):
            # reset object metadata list
            infa_object_metadata = list()
            debug("********************************************************************************")
            #debug("Validating object: {}".format(file_name), _INFO)
            debug("Parsing file: {}".format(fn), _INFO)
            debug("********************************************************************************")
            tree = ET.parse(fn)
            root = tree.getroot()

            # Extract object fields
            for childattr in root[0][0][0]:

                if childattr.tag == 'METADATAEXTENSION':
                    object_name = childattr.get('VALUE')

                if childattr.tag not in parse_tags: continue
                # FIELDATTRIBUTE is an immediate child of SOURCEFIELD or TARGETFIELD tags
                for ca in childattr.findall('FIELDATTRIBUTE'):
                    cattr_name = ca.get('NAME')
                    cattr_value = ca.get('VALUE')
                    if cattr_name != 'SforceName': continue
                    attr_field_name = cattr_value
                    infa_object_metadata.append(attr_field_name)
                    #debug(" {} Attributes - name={} value={}".format(childattr.tag, cattr_name, cattr_value), _DEBUG)

                # attr_name = childattr.get('NAME')
                # attr_datatype = childattr.get('DATATYPE')
                # attr_precision = childattr.get('PRECISION')
                # attr_scale = childattr.get('SCALE')
                # line = "NAME:"+attr_name+", DATATYPE:"+attr_datatype+", PRECISION:"+attr_precision+", SCALE:"+attr_scale
                # line = "NAME:" + attr_field_name
                # debug("Line to write into file: {}\n{}".format(file_name, line), _DEBUG)
                # debug(attr_field_name)

            debug("Object: {} metadata:".format(object_name), _INFO)
            debug(infa_object_metadata)
            return infa_object_metadata

def infa_describe_object(xml_file):

    import xml.etree.ElementTree as ET
    debug("********************************************************************************")
    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)

    parse_tags = ['SOURCEFIELD', 'TARGETFIELD']

    fn = xml_file
    file_name = os.path.basename(fn)
    #infa_metadata_file = os.path.join(infa_metadata_dir, file_name)
    debug("Processing Informatica XML file: {}".format(file_name))

    # reset object metadata list for new object
    infa_object_metadata = list()
    debug("********************************************************************************")
    #debug("Validating object: {}".format(file_name), _INFO)
    debug("Parsing file: {}".format(fn), _INFO)
    debug("********************************************************************************")
    tree = ET.parse(fn)
    root = tree.getroot()

    # Extract object fields
    for childattr in root[0][0][0]:

        if childattr.tag == 'METADATAEXTENSION':
            object_name = childattr.get('VALUE')

        if childattr.tag not in parse_tags: continue
        # FIELDATTRIBUTE is an immediate child of SOURCEFIELD or TARGETFIELD tags
        for ca in childattr.findall('FIELDATTRIBUTE'):
            cattr_name = ca.get('NAME')
            cattr_value = ca.get('VALUE')
            if cattr_name != 'SforceName': continue
            attr_field_name = cattr_value
            infa_object_metadata.append(attr_field_name)

    debug("Object: {} metadata:".format(object_name), _INFO)
    debug(infa_object_metadata)
    return infa_object_metadata

def validate_metadata(xml_files, app_properties, in_current_token, in_current_instance_url, in_current_api_version, metadata_dir):
    """
    Compare Informatica and Salesforce object metadata
    validate attribute name, datatype, precision and scale
    :return:
    """
    debug("*** Function call - {}".format(sys._getframe().f_code.co_name), _INFO)
    debug("***** Object Validation started", _INFO)
    import xml.etree.ElementTree as ET

    # report file name for validation summary across all objects
    file_name = "infa-sfdc-validation-report{}.txt".format(get_date_timestamp())
    report_file = os.path.join(metadata_dir, file_name)
    error_file_name = "infa-sfdc-validation{}.err".format(get_date_timestamp())
    error_file = os.path.join(metadata_dir, error_file_name)
    #

    for fn in xml_files:

        debug("Obtaning object name from Informatica file: {}".format(fn), _DEBUG)
        file_tree = ET.parse(fn)
        root = file_tree.getroot()
        src_tgt_element = root[0][0][0]
        #debug("src_tgt_element tag {} attributes {}".format(src_tgt_element.tag, src_tgt_element.attrib))
        dbtype = src_tgt_element.attrib.get('DATABASETYPE')
        #debug("dbtype: {}".format(dbtype), _DEBUG)
        if dbtype != "Salesforce": continue
        debug("Found DATABASETYPE = {}".format(dbtype), _DEBUG)
        object_type = src_tgt_element.tag
        for ci in src_tgt_element:
            #debug("children of src_tgt_element - tag: {} atributes: {}".format(ci.tag, ci.attrib))
            if ci.tag == 'METADATAEXTENSION':
                object_name = ci.get('VALUE')

        debug("Validating {} Object Name - {}".format(object_type, object_name), _INFO)
        with open(report_file, 'a') as fh:
            line = object_type + " Object: " + object_name
            fh.write(line + '\n')


        infa_object_metadata = infa_describe_object(fn)
        sfdc_object_metadata = sfdc_describe_object(app_properties,
                                                    in_current_token,
                                                    object_name, #'REVVY__MnContract__c',
                                                    in_current_instance_url,
                                                    in_current_api_version
                                                   )

        # compare sfdc and infa object metadata both ways
        # we need to know what is missing in infa vs sfdc and vise versa
        # generate report with results
        if not infa_object_metadata:
            debug("Informatica object metadata is missing", _DEBUG)
        elif not sfdc_object_metadata:
            debug("SFDC object metadata is missing", _DEBUG)
            line = "SFDC object metadata is missing"
            with open(report_file, 'a') as fh:
                fh.write(line + '\n')

            with open(error_file, 'a') as fhe:
                line_obj_name = object_type + " Object: " + object_name
                fhe.write(line_obj_name + '\n')
                fhe.write(line + '\n')

        else:
            infa_metadata = set(infa_object_metadata)
            sfdc_metadata = set(sfdc_object_metadata)

            # file name for object specific report
            # file_name = os.path.splitext(os.path.basename(fn))[0]
            # report_file = os.path.join(metadata_dir, file_name+"_report.txt")

            debug("Validating SFDC metadata against Informatica reference")
            infa_not_sfdc = infa_metadata - sfdc_metadata
            if infa_not_sfdc:
                debug(" Attributes missing from SFDC object: {}".format(infa_not_sfdc), _INFO)
                line = "Attributes missing from SFDC object:\n" + str(infa_not_sfdc)
                with open(report_file, 'a') as fh:
                    fh.write(line+'\n')

                with open(error_file, 'a') as fhe:
                    line_obj_name = "Object: " + object_name
                    fhe.write(line_obj_name + '\n')
                    fhe.write(line+'\n')
            else:
                debug("There are no missing attributes in SFDC org", _INFO)
                line = "There are no missing attributes in SFDC org"
                with open(report_file, 'a') as fh:
                    fh.write(line+'\n')

            debug("Validating Informatica metadata against SFDC reference")
            sfdc_not_infa = sfdc_metadata - infa_metadata
            if sfdc_not_infa:
                debug("Attributes missing from Informatica object: {}".format(sfdc_not_infa))
                line = "Attributes missing from Informatica object:\n" + str(sfdc_not_infa)
                with open(report_file, 'a') as fh:
                    fh.write(line+'\n')
            else:
                debug("There are no missing attributes in Informatica", _INFO)
                line = "There are no missing attributes in Informatica"
                with open(report_file, 'a') as fh:
                    fh.write(line + '\n')


#***** End of Functions *****

def main():

    debug("Processing application arguments", _INFO)

    # Setup parsing command line arguments and app usage help
    parseArgs = argparse.ArgumentParser(description='Provide the following parameters:')
    parseArgs.add_argument('-prop_file', type=argparse.FileType('r', encoding='UTF-8'),
                           help='Please provide json formatted properties file name', required=True,
                           default='sfdc_infa_properties.json')

    args = parseArgs.parse_args()

    # Read application properties required
    debug("Processing application properties file.", _INFO)
    app_properties = get_json_file(args.prop_file)

    debug("Searching for InformaticaIntegration properties file", _INFO)
    etl_properties = get_etl_properties()
    debug("ETL properties: {}".format(etl_properties))
    #exit(1)

    etl_client_folder = etl_properties.get("informatica.clientId")
    if etl_client_folder is None:
        debug("Folder name will be taken from application properties file", _DEBUG)
        CLIENT_FOLDER = app_properties["infa_client_folder"]
    else:
        debug("Folder name will be taken from ETL properties", _DEBUG)
        CLIENT_FOLDER = etl_client_folder


    debug("Setting up validation app deployment environment folder structure", _INFO)
    os.environ['MN_APP_BASE'] = os.path.expanduser(app_properties["app_base"])
    if os.environ.get('MN_APP_BASE') is None:
        debug("MN_APP_BASE is not defined. Set it in properties file and try again. Exiting...", _ERROR)
        exit(1)
    else:
        APP_DIR = os.environ['MN_APP_BASE']
        debug("Validation App Deployment Base directory: {}".format(APP_DIR), _INFO)
        # Define app folder structure
        app_metadata_dir = "sfdc_infa_validation"
        METADATA_DIR = os.path.join(APP_DIR, app_metadata_dir)
        APP_LOG_DIR = os.path.join(METADATA_DIR, app_properties["log_directory"])
        # INFA_METADATA_DIR = os.path.join(METADATA_DIR, 'infa_metadata')
        # SFDC_METADATA_DIR = os.path.join(METADATA_DIR, 'sfdc_metadata')

    if not os.path.isdir(METADATA_DIR):
        debug("Application Metadata directory {} does not exist and will be created".format(METADATA_DIR), _INFO)
        os.mkdir(METADATA_DIR)
    else:
        debug("Application Metadata directory {} exists".format(METADATA_DIR))

    # Check if log directiry exists
    if not os.path.isdir(APP_LOG_DIR):
        debug("Application Log directory {} does not exist and will be created".format(APP_LOG_DIR), _INFO)
        os.mkdir(APP_LOG_DIR)
    else:
        debug("Application Log directory {} exists".format(APP_LOG_DIR), _INFO)

    # if not os.path.isdir(INFA_METADATA_DIR):
    #     debug("Informatica Metadata directory {} does not exist and will be created".format(INFA_METADATA_DIR), _INFO)
    #     os.mkdir(INFA_METADATA_DIR)
    # else:
    #     debug("Informatica Metadata directory {} exists".format(INFA_METADATA_DIR), _INFO)
    #
    # if not os.path.isdir(SFDC_METADATA_DIR):
    #     debug("Salesforce Metadata directory {} does not exist and will be created".format(SFDC_METADATA_DIR), _INFO)
    #     os.mkdir(SFDC_METADATA_DIR)
    # else:
    #     debug("Salesforce Metadata directory {} exists".format(SFDC_METADATA_DIR), _INFO)

    # Enable logging
    log_file_short_name = "infa_sfdc_validation{}.log".format(get_date_timestamp())
    log_file_name = os.path.join(APP_LOG_DIR, log_file_short_name)

    logging.basicConfig(filename=log_file_name, level=logging.INFO)
    global _LOGGER
    _LOGGER = logging.getLogger()
    # end of enable logging

    # Setup Informatica ETL deployment environment
    #CLIENT_FOLDER = app_properties["infa_client_folder"]
    EXPORT_DIR = app_properties["infa_export_dir"]
    INFA_HOME = os.environ.get('INFA_HOME')
    INFA_SHARED = os.path.join(INFA_HOME, 'server/infa_shared/MN')
    INFA_CLIENT_DIR = os.path.join(INFA_SHARED, CLIENT_FOLDER)
    debug("Informatica Client folder location: {}".format(INFA_CLIENT_DIR), _INFO)

    INFA_EXPORT_DIR = os.path.join(INFA_CLIENT_DIR, EXPORT_DIR)
    debug("Check if SFDC INFA VALIDATION app export folder {} exists".format(INFA_EXPORT_DIR), _INFO)

    if os.path.isdir(INFA_EXPORT_DIR):
        debug(" Export folder {} exists".format(INFA_EXPORT_DIR), _DEBUG)
    else:
        debug(" Export folder {} does not exists, creating it".format(INFA_EXPORT_DIR), _DEBUG)
        try:
            os.mkdir(INFA_EXPORT_DIR)
        except OSError as e:
            debug("Cannot create folder {}".format(INFA_EXPORT_DIR))
            debug("Error: {}".format(str(e)), _ERROR)
            debug("Traceback: {}".format(traceback.format_exc()))
            exit(1)

    # Connect to Informatica
    # infa_connect(app_properties)

    # Get a list of objects
    # debug('Processing Informatica metadata'.format('{:*^30}'), _INFO)
    # export_objects = infa_listobjects(app_properties)
    # debug("Objects to be exported:\n{}".format('\n'.join(export_objects)), _INFO)

    # Export and process Informatica metadata

    #debug("Start Informatica metadata generation and processing", _INFO)

    infa_export(app_properties, None, INFA_EXPORT_DIR)

    # Get exported files for processing
    #all_xml_files = get_files(INFA_EXPORT_DIR, fpath=True)
    xml_files = get_infa_files(app_properties, INFA_EXPORT_DIR)
    # infa_parse_xml(app_properties, xml_files, INFA_METADATA_DIR)
    # infa_describe_all_objects(xml_files)

    # debug("Completed Informatica metadata processing", _INFO)
    # debug("********************************************************************************")

    # Get access token and instance url for subsequent calls
    current_connection = sfdc_get_token(app_properties)
    current_token = current_connection["access_token"]
    current_instance_url = current_connection["instance_url"]

    # Retrieve correct root URI version
    current_api_version = sfdc_get_versions(app_properties, current_token, current_instance_url)

    # Extract object metadata
    # sfdc_describe_object(app_properties, current_token, 'Account', current_instance_url, current_api_version)
    # sfdc_describe_object(app_properties, current_token, 'MnIRP__Exchange_Rate__c', current_instance_url, current_api_version)

    # sfdc_describe_object(app_properties, current_token, 'REVVY__MnContract__c', current_instance_url, current_api_version)


    validate_metadata(xml_files, app_properties, current_token, current_instance_url, current_api_version, METADATA_DIR)


# Main execution.
if __name__ == '__main__':
    main()