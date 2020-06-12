import os
import requests
import json
import time
import logging
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
class qrhelper(object):
    def __init__(self, qrurl, qrtoken, apiver, verify=False):
        self.qrurl = qrurl
        self.offenses = '/api/siem/offenses'
        self.offense_types = '/api/siem/offense_types'
        self.offense_closing_reasons = '/api/siem/offense_closing_reasons'
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
        #Better to verify TLS in prd. => verify=True

    def qr_get(self, endpoint_url):
        result = None
        try:
            response = requests.get(url='{}{}'.format(self.qrurl, endpoint_url), headers=self.headers, verify=self.verify)
            if response.status_code == 200:
                resp_json = json.loads(response.content)
                result = resp_json
            else:
                logger.error('Cannot get results.:{}-{}'.format(response.status_code,response.content))
        except Exception as e:
            logger.error('API Error. Failed GET:{}'.format(e))
        return result
    
    def qr_post(self, endpoint_url, params = None, data=None):
        result = None
        #data = {"query_expression": qry_ex}
        try:
            response = requests.post(url='{}{}'.format(self.qrurl, endpoint_url), params=params, data=json.dumps(data), headers=self.headers, verify=False)
            if response.status_code == 200 or response.status_code == 201:
                logger.info('POST successful to endpoint:{}'.format(endpoint_url))
                resp_json = json.loads(response.content)
                result = resp_json
            else:
                logger.error('Cannot post data.:{}-{}'.format(response.status_code,response.content))
        except Exception as e:
            logger.error('API Error. Failed POST:{}'.format(e))
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
        return qrhelper.qr_get(self, '{}{}'.format(self.offenses, filter))
    
    def get_offense_details(self, offenseid):
        return qrhelper.qr_get(self,'{}/{}'.format(self.offenses, offenseid))

    def get_offense_notes(self, offenseid):
        return qrhelper.qr_get(self,'{}/{}/notes'.format(self.offenses, offenseid))

    def get_source_addresses(self, sip_id):
        return qrhelper.qr_get(self, '{}'.format(self.source_addresses.format(sip_id)))
    
    def get_local_destination_addresses(self, dip_id):
        return qrhelper.qr_get(self, '{}'.format(self.local_destination_addresses.format(dip_id)))
    
    def get_rules(self, max_items=None):
        ##To limit max_items=99
        if max_items:
            self.headers.update({"Range": "items=0-%d" % max_items})
        return qrhelper.qr_get(self, '{}'.format(self.rules))
    
    def get_building_blocks(self, max_items=None):
        ##To limit max_items=99
        if max_items:
            self.headers.update({"Range": "items=0-%d" % max_items})
        return qrhelper.qr_get(self, '{}'.format(self.building_blocks))

    def get_rule_name(self, rule_id):
        return qrhelper.qr_get(self,'{}/{}'.format(self.rules, rule_id))

    def get_offense_types(self):
        return qrhelper.qr_get(self, '{}'.format(self.offense_types))
    
    def get_offense_type_name(self, type_id):
        types = self.get_offense_types()
        for i in types:
            if type_id == i['id']:
                index_name = i['name']
                return index_name

    def get_offense_type_property(self, type_id):
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
        return qrhelper.qr_get(self, '{}{}'.format(self.log_sources, filter))
    
    def get_refset(self, refset):
        return qrhelper.qr_get(self, '{}/sets/{}'.format(self.reference_data, refset))

    def get_refmap(self, refmap):
        # #./ReferenceDataUtil.sh create userDataMap MAP ALN
        return qrhelper.qr_get(self, '{}/maps/{}'.format(self.reference_data, refmap))
    
    def get_reftable(self, reftable):
        # #./ReferenceDataUtil.sh create UsrDataTable REFTABLE ALN -keyType=ip:IP, hostname:ALNIC, email:ALN, employeeid:ALN, vuln:ALN
        return qrhelper.qr_get(self, '{}/tables/{}'.format(self.reference_data, reftable))

    def post_refset(self, refset, value):
        #Data format should match the data type of refset - IP, ALN, etc.
        return qrhelper.qr_post(self, '{}/sets/{}?value={}'.format(self.reference_data, refset, value))

    def post_refmap(self, refmap, json_data):
        # #./ReferenceDataUtil.sh create userDataMap MAP ALN
        # # Data should be in dict with key/value static mappings: {"key":"CAN","value":"192.168.1.1"}
        return qrhelper.qr_post(self, '{}/maps/{}'.format(self.reference_data, refmap), params=json_data)

    def post_bulkrefmap(self, refmap, json_data):
        # # Data should be in Json/dict with unique keys and assigned value pairs: {"CAN":"192.168.1.1", "ADMIN":"192.168.1.1", "GUEST":"192.168.1.9"}
        return qrhelper.qr_post(self, '{}/maps/bulk_load/{}'.format(self.reference_data, refmap), data=json_data)

    def post_reftable(self, reftable, json_data):
        # # Data should be in Json/dict with outer and inner key mappings and values: {"outer_key":"CAN", "inner_key": "ip", "value":"192.168.1.1"}
        # # Dont forget key types while preparing data: UsrDataTable REFTABLE ALN -keyType=ip:IP, hostname:ALNIC, email:ALN, employeeid:ALN, vuln:ALN
        return qrhelper.qr_post(self, '{}/tables/{}'.format(self.reference_data, reftable), params=json_data)

    def post_bulkreftable(self, reftable, json_data):
        # # Data should be in Json/dict with outer/inner keys and values: {"ADMIN":{"ip":"192.168.1.1", "hostname":"ADMINSYS", "email":"admin@admin.com","employeeid":"999","vuln":"INFO-99"}}
        # # Dont forget key types while preparing data: UsrDataTable REFTABLE ALN -keyType=ip:IP, hostname:ALNIC, email:ALN, employeeid:ALN, vuln:ALN
        return qrhelper.qr_post(self, '{}/tables/bulk_load/{}'.format(self.reference_data, reftable), data=json_data)

    def post_offense_note(self, offenseid, note_text):
        return qrhelper.qr_post(self,'{}/{}/notes?note_text={}'.format(self.offenses, offenseid, note_text))
    
    def post_aql(self, qry_ex):
        search_id = None
        qry = {'query_expression': qry_ex}
        search_id = qrhelper.qr_post(self, '{}'.format(self.searches), params=qry)['search_id']
        if search_id:
            logger.info('AQL post successful.search_id:{}'.format(search_id))
        return search_id

    def get_aql_results(self, search_id):
        results = None
        qry = qrhelper.qr_get(self, '{}/{}'.format(self.searches, search_id))
        if qry and qry['status'] == 'COMPLETED':
            results = qrhelper.qr_get(self, '{}/{}/results'.format(self.searches, search_id))
        else:
            pass
        return results

    def run_aql(self, qry_ex):
    #NOTE: run_aql() can take long time and might hammer the system if you have many results or long timeframes.
    # #Therefore I limit execs up to 10 and put a sleep for 1 secs between them.
    # #If you need more/longer time frames, either change timer or use above post and later get queries using saved search_id's.
        results = None
        data = {'query_expression': qry_ex}
        search_id = qrhelper.post_aql(self, qry_ex)
        if search_id:
            timer = 0
            results = qrhelper.get_aql_results(self, search_id)
            while results == None and timer < 10:
                time.sleep(1)
                results = qrhelper.get_aql_results(self, search_id)
                timer += 1
        return results

    def close_offense(self, offense_id, closing_reason_text):
        closed = False
        response = qrhelper.qr_get(self, '{}?filter=text%3D%22{}%22'.format(self.offense_closing_reasons, closing_reason_text))
        if response:
            id = response[0]['id']
            resp_close = qrhelper.qr_post(self, '{}/{}?closing_reason_id={}&status=CLOSED'.format(self.offenses, offense_id, id))
            if resp_close and resp_close['status'] == 'CLOSED':
                logger.info('Offense Closed.Offense ID:{}'.format(offense_id))
                closed = True
            else:
                logger.error('Cannot close offense.Offense ID:{}'.format(offense_id))
        else:
            logger.error('Çannot find Closing Reason ID. Check logs and closing reason text:{}'.format(closing_reason_text))
        return closed

# #Exp Usage:
# a = qrhelper('https://192.168.1.1','token-xxxx-xxxx-xxxx-xxxxxxxxxxx','12.0')
# print(a.get_refset('QRadar Deployment'))
# print(a.post_refset('Critical Assets','192.168.199.199'))
# print(a.get_refmap('userDataMap'))
# print(a.get_reftable('UsrDataTable'))
# json_data = {"key":"CAN","value":"192.168.1.1"}
# print(a.post_refmap('userDataMap', json_data))
# json_data = {"CAN":"192.168.1.1", "ADMIN":"192.168.1.1", "GUEST":"192.168.1.9"}
# print(a.post_bulkrefmap('userDataMap', json_data))
# json_data = {"outer_key":"CAN", "inner_key": "ip", "value":"192.168.1.1"}
# print(a.post_reftable('UsrDataTable', json_data))
# json_data = {"ADMIN":{"ip":"192.168.1.1", "hostname":"ADMINSYS", "email":"admin@admin.com","employeeid":"999","vuln":"INFO-99"}}
# print(a.post_bulkreftable('UsrDataTable', json_data))
# qry = "SELECT * FROM events START '2020-06-10 10:00' STOP '2020-06-10 13:00'"
# print(a.run_aql(qry))
# a.close_offense(999,'Non-Issue')
