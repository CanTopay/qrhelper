####by CanT####
######v.5######
import os
import requests
import json
import time
import logging
import urllib3

#Enable logging
appname = os.path.basename(__file__)
formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s', "%b %d %H:%M:%S")
logger = logging.getLogger(appname)
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler('{}.log'.format(appname))
fh.setLevel(logging.DEBUG)
fh.setFormatter(formatter)
logger.addHandler(fh)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter)
logger.addHandler(ch)

#Disable ssl notifications(Enable verification in prod. Change verify=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class qradar(object):

    def __init__(self, qrurl, qrtoken, apiver, verify=False):
        self.qrurl = qrurl
        self.offenses = '/api/siem/offenses'
        self.offense_types = '/api/siem/offense_types'
        self.searches = '/api/ariel/searches'
        self.reference_data = '/api/reference_data'
        self.config = '/api/config'
        self.log_sources = '/api/config/event_sources/log_source_management/log_sources'
        self.rules = '/api/analytics/rules'
        self.building_blocks = '/api/analytics/building_blocks'
        self.source_addresses = '/api/siem/source_addresses/{}'
        self.local_destination_addresses = '/api/siem/local_destination_addresses/{}'
        self.headers = {"Accept": "application/json", "Content-Type": "application/json", "Version": apiver ,"SEC": qrtoken}
        self.verify = verify

    def qry_get(self, endpoint_url):
        result = None
        try:
            response = requests.get(url='{}{}'.format(self.qrurl, endpoint_url), headers=self.headers, verify=self.verify)
            logger.info('Query executed.:{}'.format(response.status_code))
            if response.status_code == 200:
                resp_json = json.loads(response.content)
                result = resp_json
            else:
                logger.error('Cannot get results.:{}-{}'.format(response.status_code,response.content))
        except Exception as e:
            logger.error('API Error. Failed GET:{}'.format(e))
        return result

    def get_offenses(self, max_items=None, open=None):
        ## https://server.com/api/siem/offenses?filter=status%3D%22OPEN%22
        ##To limit max_items=99
        if max_items:
            self.headers.update({"Range": "items=0-%d" % max_items})
        ##To filter Closed offenses open=True
        if open is True:
            filter = '?filter=status%3D%22OPEN%22'
        else:
            filter = ''
        return qradar.qry_get(self, '{}{}'.format(self.offenses, filter))
    
    def get_offense_details(self, offenseid):
        return qradar.qry_get(self,'{}/{}'.format(self.offenses, offenseid))

    def get_offense_notes(self, offenseid):
        return qradar.qry_get(self,'{}/{}/notes'.format(self.offenses, offenseid))

    def get_source_addresses(self, sip_id):
        return qradar.qry_get(self, '{}'.format(self.source_addresses.format(sip_id)))
    
    def get_local_destination_addresses(self, dip_id):
        return qradar.qry_get(self, '{}'.format(self.local_destination_addresses.format(dip_id)))
    
    def get_rules(self, max_items=None):
        ##To limit max_items=99
        if max_items:
            self.headers.update({"Range": "items=0-%d" % max_items})
        return qradar.qry_get(self, '{}'.format(self.rules))
    
    def get_building_blocks(self, max_items=None):
        ##To limit max_items=99
        if max_items:
            self.headers.update({"Range": "items=0-%d" % max_items})
        return qradar.qry_get(self, '{}'.format(self.building_blocks))

    def get_rule_name(self, rule_id):
        return qradar.qry_get(self,'{}/{}'.format(self.rules, rule_id))

    def get_offense_types(self):
        return qradar.qry_get(self, '{}'.format(self.offense_types))
    
    def check_offense_type_name_in_offense(self, type_id):
        types = self.get_offense_types()
        for i in types:
            if type_id == i['id']:
                index_name = i['name']
                return index_name

    def check_offense_type_property_in_offense(self, type_id):
        types = self.get_offense_types()
        for i in types:
            if type_id == i['id']:
                index_name = i['property_name']
                return index_name

    def get_logsources(self, max_items=None, enabled=None):
        ##https://server.com/api/siem/offenses?filter=status%3D%22OPEN%22
        ##To filter disabled enabled=True.
        ##To limit max_items=99
        if max_items:
            self.headers.update({"Range": "items=0-%d" % max_items})
        if enabled is True:
            filter = '?filter=enabled%3Dtrue'
        else:
            filter = ''
        return qradar.qry_get(self, '{}{}'.format(self.log_sources, filter))

a = qradar('https://192.168.0.246','745a0975-d47f-4340-b821-26e1888f1355','12.0')
print(a.get_logsources(enabled=True))





#     def post_offense_note(self, offense_id, note_text):
#         try:
#             response = requests.post(url=self.offenses_endpoint + '/{}/notes?note_text={}'.format(offense_id, str(note_text))
#                                      , headers=self.headers, verify=False)
#             if response.status_code == 201:
#                 resp_json = json.loads(response.content)
#                 return resp_json
#             else:
#                 #print(response.status_code, ":Error getting offenses: ", response.content)
#                 lgr.error('QRadar API Response Error: ' + str(response.status_code) + ' - ' + str(response.content))
#         except Exception as e:
#             lgr.error('Rest API Error - Failed to connect QRadar URL:' + str(e))
#             sys.exit(1)



#     def run_aql(self, qry_ex):
#         try:
#             data = {"query_expression": qry_ex}
#             response = requests.post(self.search_endpoint, params=(data), headers=self.headers, verify=False)
#             if response.status_code == 201:
#                 resp_json = json.loads(response.content)
#                 search_id = resp_json["search_id"]
#                 if search_id:
#                     resp_sid = requests.get(url=self.search_endpoint + "/" + search_id, headers=self.headers,verify=False)
#                     if resp_sid.status_code == 200:
#                         resp_sid_json = json.loads(resp_sid.content)
#                         error = False

#                         while resp_sid_json["status"] != "COMPLETED" and not error:
#                             try:
#                                 if (resp_sid_json["status"] == "EXECUTE") | (resp_sid_json["status"] == "SORTING") | (
#                                         resp_sid_json["status"] == "WAIT"):
#                                     time.sleep(1)
#                                     resp_sid_recheck = requests.get(url=self.search_endpoint + "/" + search_id,
#                                                                     headers=self.headers, verify=False)
#                                     resp_sid_json = json.loads(resp_sid_recheck.content)
#                                     error = False
#                                 else:
#                                     error = True
#                                     lgr.error('QRadar AQL Search did not finished! - ' + str(resp_json["status"]))
#                             except Exception as e:
#                                 lgr.error('QRadar AQL Search Failed! - ' + str(resp_json["status"]) + ' - ' + str(e))

#                         if resp_sid_json["status"] == "COMPLETED":
#                             qry_results = requests.get(url=self.search_endpoint + "/" + search_id + "/results",
#                                                        headers=self.headers, verify=False)
#                             if qry_results.status_code == 200:
#                                 qry_results_json = json.loads(qry_results.content)
#                                 return qry_results_json
#                             else:
#                                 lgr.error('Error at getting search results. ResultSet - ' + str(qry_results.status_code) + ' - ' + str(qry_results.content))
#                     else:
#                         lgr.error('Error at getting complete status for search. Search - ' + str(resp_sid.status_code) + ' - ' + str(resp_sid.content))
#                         response.close()
#             else:
#                 lgr.error('Error at Posting AQL search to Rest API - ' + str(response.status_code))
#                 response.close()
#                 sys.exit(1)
#         except Exception as e:
#             lgr.error('Error at REST API Call - ' + str(e))
#             sys.exit(1)

#     def run_aql_get_status(self, qry_ex):
#         try:
#             data = {"query_expression": qry_ex}
#             response = requests.post(self.search_endpoint, params=(data), headers=self.headers, verify=False)
#             if response.status_code == 201:
#                 resp_json = json.loads(response.content)
#                 search_id = resp_json["search_id"]
#                 if search_id:
#                     resp_sid = requests.get(url=self.search_endpoint + "/" + search_id, headers=self.headers,verify=False)
#                     if resp_sid.status_code == 200:
#                         resp_sid_json = json.loads(resp_sid.content)
#                         error = False
#                         while resp_sid_json["status"] != "COMPLETED" and not error:
#                             try:
#                                 if (resp_sid_json["status"] == "EXECUTE") | (resp_sid_json["status"] == "SORTING") | (
#                                         resp_sid_json["status"] == "WAIT"):
#                                     time.sleep(1)
#                                     resp_sid_recheck = requests.get(url=self.search_endpoint + "/" + search_id,
#                                                                     headers=self.headers, verify=False)
#                                     resp_sid_json = json.loads(resp_sid_recheck.content)
#                                     error = False
#                                 else:
#                                     error = True
#                                     lgr.error('QRadar AQL Search did not finished! - ' + str(resp_json["status"]))
#                             except Exception as e:
#                                 lgr.error('QRadar AQL Search Failed! - ' + str(resp_json["status"]) + ' - ' + str(e))

#                         if resp_sid_json["status"] == "COMPLETED":
#                             return resp_sid_json
#                     else:
#                         lgr.error('Error at getting complete status for search. Search - ' + str(resp_sid.status_code) + ' - ' + str(resp_sid.content))
#                         response.close()
#             else:
#                 lgr.error('Error at Posting AQL search to Rest API - ' + str(response.status_code))
#                 response.close()
#                 sys.exit(1)
#         except Exception as e:
#             lgr.error('Error at REST API Call - ' + str(e))
#             sys.exit(1)

#     def post_aql(self, qry_ex):
#         try:
#             data = {"query_expression": qry_ex}
#             response = requests.post(self.search_endpoint, params=(data), headers=self.headers, verify=False)
#             if response.status_code == 201:
#                 resp_json = json.loads(response.content)
#                 search_id = resp_json["search_id"]
#                 if search_id:
#                     lgr.info('AQL search posted - search ID: {}'.format(search_id))
#                     return search_id
#                 else:
#                     lgr.error('Error at getting AQL search ID: {} - {}'.format(response.status_code,response.content))
#                     response.close()
#             else:
#                 lgr.error('Error at Posting AQL search to Rest API: {} - {}'.format(response.status_code,response.content))
#                 response.close()
#         except Exception as e:
#             lgr.error('Error at REST API Call - ' + str(e))
#             sys.exit(1)

#     def get_aql_results(self, search_id):
#         try:
#             resp_sid = requests.get(url=self.search_endpoint + "/" + str(search_id), headers=self.headers, verify=False)
#             if resp_sid.status_code == 200:
#                 resp_sid_json = json.loads(resp_sid.content)
#                 if resp_sid_json["status"] == "COMPLETED":
#                     qry_results = requests.get(url=self.search_endpoint + "/" + search_id + "/results",
#                                                headers=self.headers, verify=False)
#                     if qry_results.status_code == 200:
#                         qry_results_json = json.loads(qry_results.content)
#                         return qry_results_json
#                     else:
#                         lgr.error('Error at getting AQL Search Results. ResultSet - ' + str(
#                             qry_results.status_code) + ' - ' + str(qry_results.content))
#                 else:
#                     resp_sid.close()
#             else:
#                 lgr.error('Error at AQL search status - {} - Error:{}'.format(resp_sid.status_code, resp_sid))
#                 resp_sid.close()
#         except Exception as e:
#             lgr.error('Error at REST API Call - ' + str(e))
#             sys.exit(1)


#     def close_offense(self, offense_id, closing_reason_id):
#         closed = False
#         try:
#             ##https://test.com/api/siem/offenses/22785?closing_reason_id=104&status=CLOSED
#             response = requests.post(url=self.offenses_endpoint + '/{}?closing_reason_id={}&status=CLOSED'.format(offense_id, closing_reason_id),
#                                      headers=self.headers, verify=False)
#             if response.status_code == 200:
#                 resp_json = json.loads(response.content)
#                 if resp_json['status'] == 'CLOSED':
#                     lgr.info('QRadar Offense Closed:{}'.format(offense_id))
#                     closed = True
#             else:
#                 #print(response.status_code, ":Error getting offenses: ", response.content)
#                 lgr.error('QRadar API Response Error:{} - {}'.format(response.status_code, response.content))
#             return closed
#         except Exception as e:
#             lgr.error('Rest API Error - Failed to connect QRadar URL:{}'.format(e))
            #sys.exit(1)

#     def get_offense_users(self, offense_id, limit, starttime, endtime):
#         username = []
#         qry = "SELECT username FROM events WHERE inOffense({}) GROUP BY username LIMIT {} START '{}' STOP '{}'"
#         aql_res = self.run_aql(qry.format(offense_id, limit, starttime, endtime))
#         for k, v in aql_res.items():
#             for i in v:
#                 for key, val in i.items():
#                     if key == 'username':
#                         username.append(val)
#         return username
            
    # #curl -s -X POST -u username -H 'Version: 9.1' -H 'Accept: application/json' 'https://example.com/api/siem/offenses/123?closing_reason_id=42&status=CLOSED'
    # a = qradar()
    # a.close_offense(9683, 54)
    # # COMMENTED OUT - AQL TIME TOO LONG
    # # "SELECT destinationip FROM events WHERE inOffense(5046) GROUP BY destinationip START '2019-06-06 10:00' STOP '2019-06-06 13:00'"
    # # SELECT UTF8(payload) as MessageBody FROM events WHERE inOffense(25312) GROUP BY MessageBody LIMIT 10 START '2019-09-05 08:00' STOP '2019-09-05 10:00'
    # # {'events': [{'destinationip': '94.236.112.192'}]}
    # def get_offense_remote_destination(self, offense_id, limit, starttime, endtime):
    #     dest_ip = []
    #     qry = "SELECT destinationip FROM events WHERE inOffense({}) GROUP BY destinationip LIMIT {} START '{}' STOP '{}'"
    #     aql_res = self.post_aql(qry.format(offense_id, limit, starttime, endtime))
    #     for k, v in aql_res.items():
    #         for i in v:
    #             for key, val in i.items():
    #                 if key == 'destinationip':
    #                     dest_ip.append(val)
    #     return dest_ip

##BASIC USAGE##########
# qr = qradar()
# closing_reason_id = 104
# offense_id = '22787'
# a = qr.close_offense(offense_id, closing_reason_id)
# print(a)
# a = qr.get_offenses(2, True)
# for i in a:
#     status = i['status']
#     print(status)
# a = qr.get_aql_results('6b7ed58b-db1e-4046-aed3-f5af9fed4f1e')
# print(a)
# # get_rules = qr.get_rules()
# # #print(get_rules)
# # for i in get_rules:
# #     if i['enabled'] == True and i['origin'] != 'SYSTEM':
# #         print(i['name'])
# # get_offenses = qr.get_offenses()
# # for i in get_offenses:
# #      print(i)
# #     print(i['id'])
# #     print(i['description'])
# # get_offense_notes = qr.get_offense_notes(10242)
# # print(get_offense_notes)
# # for i in get_offense_notes:
# #     print(i['note_text'])
# # post_offense_note = qr.post_offense_note(10242, 'dalaylama')
# # off_details = qr.get_offense_details(10241)
# # print(off_details)
# # off_type = qr.get_offense_types()
# # for i in off_type:
# #     print(i['id'])
# a = qr.get_source_addresses(10)
# print(a)
# a = qr.get_rule_name(104884)
# print(a)
# q = "SELECT destinationip FROM events WHERE inOffense(5046) GROUP BY destinationip START '2019-06-06 10:00' STOP '2019-06-06 13:00'"
# # a = qr.run_aql(q)
# #a = qr.post_aql(q)
# b = qr.get_aql_results('23cad12e-da8b-49d4-9378-27f35f929254')
# print(b)
# q = "SELECT sourcemac FROM events WHERE inOffense(25259) GROUP BY sourcemac START '2019-08-30 11:00' STOP '2019-08-30 13:00'"
# a = qr.post_aql(q)
# print(a)
##9d2a90b7-1a17-4646-a2b1-c3fca1930c7c
# def parse_get_aql(get_aql_results, target_item):
#     values_list = []
#     for i in get_aql_results['events']:
#         for k,v in i.items():
#             if k == target_item:
#                 if v != None:
#                     values_list.append(v)
#     return values_list
#
# sourcemacs = qr.get_aql_results('9d2a90b7-1a17-4646-a2b1-c3fca1930c7c')
#
# retval = parse_get_aql(sourcemacs, 'sourcemac')
# print(retval)
# a = qr.get_offense_remote_destination_search_results('54f0ac63-2202-4f32-9e3d-3e7d3297709c')
# print(a)
