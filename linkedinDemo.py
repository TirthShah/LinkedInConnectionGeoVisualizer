# -*- coding: utf-8 -*-
# code snippet references: https://github.com/ozgur/python-linkedin/blob/master/linkedin/linkedin.py
import contextlib
import hashlib
import random
import urllib
import requests
from requests_oauthlib import OAuth1
import collections
from utils import enum, to_utf8, raise_for_error, StringIO
import ast
# from apiclient.discovery import build

AccessToken = collections.namedtuple('AccessToken', ['access_token', 'expires_in'])
__all__ = ['LinkedInAuthentication', 'LinkedInApplication', 'PERMISSIONS']

PERMISSIONS = enum('Permission',
                        BASIC_PROFILE='r_basicprofile',
                        FULL_PROFILE='r_fullprofile',
                        EMAIL_ADDRESS='r_emailaddress',
                        NETWORK='r_network',
                        CONTACT_INFO='r_contactinfo',
                        NETWORK_UPDATES='rw_nus',
                        GROUPS='rw_groups',
                        MESSAGES='w_messages')

ENDPOINTS = enum('LinkedInURL',
                      PEOPLE='https://api.linkedin.com/v1/people',
                      PEOPLE_SEARCH='https://api.linkedin.com/v1/people-search',
                      GROUPS='https://api.linkedin.com/v1/groups',
                      POSTS='https://api.linkedin.com/v1/posts',
                      COMPANIES='https://api.linkedin.com/v1/companies',
                      COMPANY_SEARCH='https://api.linkedin.com/v1/company-search',
                      JOBS='https://api.linkedin.com/v1/jobs',
                      JOB_SEARCH='https://api.linkedin.com/v1/job-search')

NETWORK_UPDATES = enum('NetworkUpdate',
                            APPLICATION='APPS',
                            COMPANY='CMPY',
                            CONNECTION='CONN',
                            JOB='JOBS',
                            GROUP='JGRP',
                            PICTURE='PICT',
                            EXTENDED_PROFILE='PRFX',
                            CHANGED_PROFILE='PRFU',
                            SHARED='SHAR',
                            VIRAL='VIRL')

class LinkedInDeveloperAuthentication(object):
    """
    Uses all four credentials provided by LinkedIn as part of an OAuth 1.0a
    flow that provides instant API access with no redirects/approvals required.
    Useful for situations in which users would like to access their own data or
    during the development process.
    """
    def __init__(self, consumer_key, consumer_secret, user_token, user_secret,
                 redirect_uri, permissions=[]):
        self.consumer_key = consumer_key
        self.consumer_secret = consumer_secret
        self.user_token = user_token
        self.user_secret = user_secret
        self.redirect_uri = redirect_uri
        self.permissions = permissions

class LinkedInAuthentication(object):
    """
    Implements a standard OAuth 2.0 flow that involves redirection for users to
    authorize the application to access account data.
    """
    AUTHORIZATION_URL = 'https://www.linkedin.com/uas/oauth2/authorization'
    ACCESS_TOKEN_URL = 'https://www.linkedin.com/uas/oauth2/accessToken'

    def __init__(self, key, secret, redirect_uri, permissions=None):
        self.key = key
        self.secret = secret
        self.redirect_uri = redirect_uri
        self.permissions = permissions or []
        self.state = None
        self.authorization_code = None
        self.token = None
        self._error = None

    @property
    def authorization_url(self):
        self.state = self._make_new_state()
        qd = {'response_type': 'code',
              'client_id': self.key,
              'scope': (' '.join(self.permissions)).strip(),
              'state': self.state,
              'redirect_uri': self.redirect_uri}
        # urlencode uses quote_plus when encoding the query string so,
        # we ought to be encoding the qs by on our own.
        qsl = ['%s=%s' % (urllib.quote(k), urllib.quote(v)) for k, v in qd.items()]
        return '%s?%s' % (self.AUTHORIZATION_URL, '&'.join(qsl))

    @property
    def last_error(self):
        return self._error

    def _make_new_state(self):
        return hashlib.md5(
            '%s%s' % (random.randrange(0, 2 ** 63), self.secret)).hexdigest()

    def get_access_token(self, timeout=60):
        assert self.authorization_code, 'You must first get the authorization code'
        qd = {'grant_type': 'authorization_code',
              'code': self.authorization_code,
              'redirect_uri': self.redirect_uri,
              'client_id': self.key,
              'client_secret': self.secret}
        response = requests.post(self.ACCESS_TOKEN_URL, data=qd, timeout=timeout)
        raise_for_error(response)
        response = response.json()
        self.token = AccessToken(response['access_token'], response['expires_in'])
        return self.token

class LinkedInSelector(object):
    @classmethod
    def parse(cls, selector):
        with contextlib.closing(StringIO()) as result:
            if type(selector) == dict:
                for k, v in selector.items():
                    result.write('%s:(%s)' % (to_utf8(k), cls.parse(v)))
            elif type(selector) in (list, tuple):
                result.write(','.join(map(cls.parse, selector)))
            else:
                result.write(to_utf8(selector))
            return result.getvalue()

class LinkedInApplication(object):
    BASE_URL = 'https://api.linkedin.com'

    def __init__(self, authentication=None, token=None):
        assert authentication or token, 'Either authentication instance or access token is required'
        self.authentication = authentication
        if not self.authentication:
            self.authentication = LinkedInAuthentication('', '', '')
            self.authentication.token = AccessToken(token, None)
            print "User Authenticated Successfully!"

    def make_request(self, method, url, data=None, params=None, headers=None,
                     timeout=60):
        if headers is None:
            headers = {'x-li-format': 'json', 'Content-Type': 'application/json'}
        else:
            headers.update({'x-li-format': 'json', 'Content-Type': 'application/json'})

        if params is None:
            params = {}
        kw = dict(data=data, params=params,
                  headers=headers, timeout=timeout)

        if isinstance(self.authentication, LinkedInDeveloperAuthentication):
            # Let requests_oauthlib.OAuth1 do *all* of the work here
            auth = OAuth1(self.authentication.consumer_key, self.authentication.consumer_secret,
                          self.authentication.user_token, self.authentication.user_secret)
            kw.update({'auth': auth})
        else:
            params.update({'oauth2_access_token': self.authentication.token.access_token})

        return requests.request(method.upper(), url, **kw)
        
        """
        Calls the LinkedIn Connections API
        """
    def get_connections(self, member_id=None, member_url=None, selectors=None,
                        params=None, headers=None):
        if member_id:
            url = '%s/id=%s/connections' % (ENDPOINTS.PEOPLE, str(member_id))
        elif member_url:
            url = '%s/url=%s/connections' % (ENDPOINTS.PEOPLE,
                                             urllib.quote_plus(member_url))
        else:
            url = '%s/~/connections' % ENDPOINTS.PEOPLE
        if selectors:
            url = '%s:(%s)' % (url, LinkedInSelector.parse(selectors))

        response = self.make_request('GET', url, params=params, headers=headers)
        raise_for_error(response)
        print "Connections API called successfully!"
        return response.json()

firstName = []
lastName = []
industry = []
pictureUrl = []
locationName = []
"""
Parse Connections JSON to extract fields of interest
"""
def parse_linkedin_connections(vals):
    counter =1
    private=0
    
    AllInfo = open('IgnoreThisFile.txt','a+')
    
    a = iter(vals)
    for i in a:
        if i['firstName'] != 'private':

            firstName.append(i['firstName'])
            locationName.append(i['location']['name'])
            
            try:
                AllInfo.write(i['firstName']+" "+i['lastName']+"\n")
                lastName.append(i['lastName'])                
            except:
                content = i['lastName'].encode('ascii', 'ignore')
                lastName.append(content)
                AllInfo.write(i['firstName']+" "+content+"\n")
                
            try:
                AllInfo.write(i['industry']+"\n")
                industry.append(i['industry'])                    
            except:
                industry.append("Unspecified")
                AllInfo.write("Unspecified"+"\n")
                
            try:
                AllInfo.write(i['pictureUrl']+"\n")
                pictureUrl.append(i['pictureUrl'])                    
            except:
                pictureUrl.append("http://fusiondigital.files.wordpress.com/2010/07/linkedin-icon.png")
                AllInfo.write("http://fusiondigital.files.wordpress.com/2010/07/linkedin-icon.png"+"\n")
                
            counter = counter+1 
        else:
            private = private +1    

    AllInfo.close();
    print "Total Connections: "+str(counter+private)+"    Private Connections: "+str(private)+ "    Public Connections: "+str(counter)


"""
Convert location to Geocode using Google's RESTful API
"""
def get_geocodes(api_key, location):
        url = 'https://maps.googleapis.com/maps/api/geocode/json?address='+location+'&key='+api_key
        response = requests.get(url)
        return response.json()

"""
Exract Geocodes and write it to file
"""
def write_to_file(fileObject, loc_json):
    lat = loc_json['results'][0]['geometry']['location']['lat']
    lng = loc_json['results'][0]['geometry']['location']['lng']
    latitude.append(lat)
    longitude.append(lng)
    fileObject.write(str(lat)+" "+str(lng)+"\n")

latitude = []
longitude =[]

"""
Write Geocodes in pre-defined format to a file
""" 
def write_geocodes(api_key): 
    b = iter(locationName)
    f = open('GeoCodes.txt','a+')
    counter2=1
    
    for j in b:
        #ATTEMPT 1:
        loc_json = get_geocodes(api_key, j)
                
        #SUCCESS
        if loc_json['status'] == 'OK':
            write_to_file(f, loc_json)
        #FAILURE    
        else:
            retry=1
            while (loc_json['status'] != 'OK' and retry<5):#RETRY 5 times or until request is successful 
                loc_json = get_geocodes(api_key, j)
                retry = retry +1
            
            if loc_json['status'] == 'OK':
                write_to_file(f, loc_json)
                
            else: # CLEAN corresponding connections data
                firstName[counter2]=""
                lastName[counter2]=""
                industry[counter2]=""
                pictureUrl[counter2]=""                         
       
        counter2 = counter2+1
    f.close() 
    print "\nGeo-codes written to GeoCodes.txt successfully!"   

"""
Write ConnectionsInfo in pre-defined format to a file
""" 
def write_connections_info():
    
    NameFile = open('Name.txt','a+')
    IndustryFile = open('Industry.txt','a+')
    IconFile = open('Icon.txt','a+')
     
    for i, val in enumerate(firstName):
        NameFile.write(val+" "+lastName[i]+"\n")
        IndustryFile.write(industry[i]+"\n") 
        IconFile.write(pictureUrl[i]+"\n")

    NameFile.close(); IndustryFile.close(); IconFile.close();
    print "Connections Info written to files"

if __name__ == '__main__':
    #Refer: http://developer.linkedin.com/documents/authentication 
    API_KEY = ''
    API_SECRET = ''
    USER_TOKEN = ''
    USER_SECRET = ''
    RETURN_URL = ''
    #Google API Developer-Key: https://developers.google.com/api-client-library/python/guide/aaa_apikeys
    api_key = ''
    
    #Authenticate the user
    authentication = LinkedInDeveloperAuthentication(API_KEY, API_SECRET, USER_TOKEN, USER_SECRET, RETURN_URL,
                                            PERMISSIONS.enums.values())
    linkedInApplication = LinkedInApplication(authentication=authentication)

    #Get all connections of the authenticated user
    connectionsInfo = linkedInApplication.get_connections()
    print "Connections Info:"
    print connectionsInfo
    
    print "\nParsing connections Info ..."
    #Extract field of interest from JSON 
    vals = connectionsInfo['values']
    parse_linkedin_connections(vals)
    print "\nParsing complete."
    
    print"\nWriting GeoCodes to text file..."
    # Write GeoCodes
    write_geocodes(api_key)
    
    print"\nWriting Connections Info to text files..."
    write_connections_info()
     
    print "\nPlease open ConnectionsHeatMap.html and browse open GeoCodes.txt from the bottom of the webpage."
    print "To visualize Toggle HeatMap button twice."
    
    print "\nPlease open ConnectionsInfoMap.html and browse open GeoCodes.txt, Name.txt, Icon.txt and Industry.txt from the bottom of the webpage."
    print "The detailed information can be viewed by hovering on the icon."