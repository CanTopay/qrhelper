####by CanT####
######v.5######
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
#Better to enable verification in prd. => verify=True
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
    
    def qr_post(self, endpoint_url, data=None):
        result = None
        #data = {"query_expression": qry_ex}
        try:
            response = requests.post(url='{}{}'.format(self.qrurl, endpoint_url), params=(data), headers=self.headers, verify=False)
            if response.status_code == 201:
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
    
    def check_offense_type_name(self, type_id):
        types = self.get_offense_types()
        for i in types:
            if type_id == i['id']:
                index_name = i['name']
                return index_name

    def check_offense_type_property(self, type_id):
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

    def post_offense_note(self, offenseid, note_text):
        return qrhelper.qr_post(self,'{}/{}/notes?note_text={}'.format(self.offenses, offenseid, note_text))
    
    def post_aql(self, qry_ex):
        search_id = None
        data = {'query_expression': qry_ex}
        search_id = qrhelper.qr_post(self, '{}'.format(self.searches), data=data)['search_id']
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
    # #Therefore I limited execs to 10 and put a sleep for 1 secs between execs.
    # #If you need longer time frames; use above post/get_aql queries by keeping-posting the search_id's.
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
            try:
                response = requests.post(url='{}{}/{}?closing_reason_id={}&status=CLOSED'.format(self.qrurl, self.offenses, offense_id, id),
                headers=self.headers, verify=self.verify)
                if response.status_code == 200:
                    resp_json = json.loads(response.content)
                    if resp_json['status'] == 'CLOSED':
                        logger.info('Offense Closed.Offense ID:{}'.format(offense_id))
                        closed = True
                else:
                    logger.error('Cannot post data.:{}-{}'.format(response.status_code,response.content))
            except Exception as e:
                logger.error('API Error. Failed POST:{}'.format(e))
        else:
            logger.error('Çannot find Closing Reason ID. Check logs and closing reason text:{}'.format(closing_reason_text))
        return closed

# a = qrhelper('https://192.168.0.246','745a0975-d47f-4340-b821-26e1888f1355','12.0')
# #qry = "SELECT * FROM events START '2020-06-10 10:00' STOP '2020-06-10 13:00'"
# #a.run_aql(q)
# a.close_offense(1,'Non-Issue')
