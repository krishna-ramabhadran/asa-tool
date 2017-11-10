#!/usr/bin/python
import getpass
import os
import json
import time
import sys
import argparse
import logging
import requests
import base64
import urllib2
import random

logging.basicConfig(filename='logging_FW_Script.log',format='%(asctime)s : %(message)s',level=20,datefmt='%m/%d/%Y %I:%M:%S %p')
os.system('clear')
change=0
headers = {'Content-Type': 'application/json'}
server = {'vpn':'https://10.10.10.1'}
api_path={'object': '/api/objects/networkobjects/', 'object-group': '/api/objects/networkobjectgroups/'}   
url = server
f = None
username=os.getlogin()
firewall=raw_input(('\nPlease choose which FW to connect to:\n\n1.Calgary Edge FW(cf)\n2.Victoria Edge FW(vf)\n3.DUS Edge FW(df)\n4.Victoria VPN FW(vicvpn)\n5.Calgary OPS VPN FW(opsvpn)\n\nChoose the firewall code:')).lower()
if firewall not in server.keys():
        print('\n###################Wrong selection.Exiting the script!##########################\n')
        sys.exit(-2)
server=server[firewall]
print('\nEnter the password to connect to '+server+':')
password=getpass.getpass()
def set_server(path):
        global req
        url=server+path
        req = urllib2.Request(url, None, headers)
        base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
        req.add_header("Authorization", "Basic %s" % base64string)
        return req
def read_data(req,value):
        try:
                f = urllib2.urlopen(req)
                status_code = f.getcode()
                if (status_code != 200):
                                print 'Error in get. Got status code: '+status_code
                resp = f.read()
                json_resp = json.loads(resp)
                if value==1:
                        print json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': '))
                return json_resp
        finally:
                if f:  f.close()
def search_data():
        temp=0
        type=raw_input('You want to search with value or name?')
        print('Enter')
        json_resp=read_data(0)
        print('\nSearching for item:'+value+'....')
        for i in range(0,len(json_resp['items'])):
                if value in json_resp['items'][i]['host']['value']:
                        print json_resp['items'][i]['objectId']
                        temp=1
        if temp!=1:
                print('The item:'+value+' not found\n')
                return 0
        else:
                return 1

def make_data():
        api_path={'object': '/api/objects/networkobjects/', 'object-group': '/api/objects/networkobjectgroups/'}
        if raw_input(('\nWould you want to add an object/object-group?')).lower()=='yes':
                choice='yes'
                while choice=='yes':
                        type=raw_input('Enter the object type(Object/Object-Group/ACL):').lower()
                        url=server+api_path[type]
                        name=raw_input('Enter the '+type+' name:')
                        value=raw_input('Enter the '+type+' value(Leave a space between to enter multiple values, Use /32 mask for host):')
                        if type=='object-group':
                                type='object#NetworkObjGroup'
                        elif type=='object':
                                type='object#NetworkObj'
                        json_data={}
                        if type=='object#NetworkObjGroup':
                                json_data['kind']=type
                                json_data['name']=name
                                json_data['members']=[]
                                for i in value.split(): 
                                        if '/32' in i:
                                                json_data['members'].append({ 'kind': 'IPv4Address','value':i})
                                        else:
                                                json_data['members'].append({ 'kind': 'IPv4Network','value':i})
                                json_data['objectId']=name
                                #print json_data
                                write_data(json_data,url)
                                choice=raw_input('Do you want to continue adding more object/object-group?').lower()
                        elif  type=='object#NetworkObj':
                                if '/32' in value:
                                        json_data['host']={ 'kind': 'IPv4Address','value':value.split('/32')[0]}
                                else:
                                        json_data['host']={ 'kind': 'IPv4Network','value':value}
                                json_data['name']=name
                                json_data['kind']=type
                                json_data['objectId']=name
                                print url
                                write_data(json_data,url)
                                choice=raw_input('Do you want to continue adding more object/object-group?').lower()
        choice='yes'
        if raw_input(('\nWould you want to add a Firewall Access-List?')).lower()=='yes':
                while choice=='yes':
                        api_path = '/api/access/in'
                        object_type={'object-group':'objectRef#NetworkObjGroup','object':'objectRef#NetworkObj'}
                        req=set_server(api_path)
                        json_resp=read_data(req,0)
                        for i in json_resp['items']:
                                print('\nINBOUND ACCESS-LIST:'+i['ACLName']+' is appied to the interface '+i['interface']['name'])
                        print(" ")
                        api_path = '/api/access/out'
                        req=set_server(api_path)
                        json_resp=read_data(req,0)
                        for i in json_resp['items']:
                                print('\nOUTBOUND ACCESS-LIST:'+i['ACLName']+' is appied to the interface '+i['interface']['name'])
                        print(" ")
                        interface=raw_input('\nEnter the interface name(Matching the output above):')
                        direction=raw_input('\nEnter the direction(in/out):').lower()
                        source_object=raw_input('\nEnter the source address(object/object-group name):')
                        sobject_type=raw_input('\nEnter the type of '+source_object+'[Default:object-group]:')
                        if sobject_type=='':
                                sobject_type='object-group'
                        dest_object=raw_input('\nEnter the destination address(object/object-group name):')
                        dobject_type=raw_input('\nEnter the type of '+dest_object+'[Default:object-group]:')  
                        if dobject_type=='':
                                dobject_type='object-group'
                        protocol=raw_input('\nEnter the protocol type(tcp\udp\Tcpudp\ip)').lower()
                        dest_port=raw_input('\nEnter the destination port:')
                        action=raw_input('\nPermit/Deny the traffic?').lower()
                        action='true' if action=='permit' else 'false'
                        api_path = '/api/access/'+direction+'/'+interface+'/rules'
                        url=server+api_path
                        req=set_server(api_path)
                        json_data={}
                        json_data['active']='true'
                        json_data['permit']=action
                        json_data['ruleLogging']={}
                        json_data['destinationAddress']={"kind": object_type[dobject_type],"objectId": dest_object}
                        json_data['sourceAddress']={"kind": object_type[sobject_type],"objectId": source_object}
                        json_data['destinationService']={"kind": "TcpUdpService","value":protocol+'/'+dest_port}
                        write_data(json_data,url)
                        choice=raw_input('\nDo you want to continue adding more Firewall Rules?').lower()
def write_data(post_data,url):
        global change
        print('\n----------------CONFIGURATION----------------')
        print json.dumps(post_data,sort_keys=True,indent=4, separators=(',', ': '))
        print('\n---------------------------------------------')
        choice=raw_input('\nWould you want to push the above config to the the firewall?').lower()
        if choice=='yes':
                req = urllib2.Request(url, json.dumps(post_data), headers)
                base64string = base64.encodestring('%s:%s' % (username, password)).replace('\n', '')
                req.add_header("Authorization", "Basic %s" % base64string)   
                try:
                        f  = urllib2.urlopen(req)
                        status_code = f.getcode()
                        #print "Status code is "+str(status_code)
                        if status_code == 201:
                                print "\nAbove configuration pushed to firewall successfully."
                                change=1
                except urllib2.HTTPError, err:
                        print "Error received from server. HTTP Status code :"+str(err.code)
                        try:
                                json_error = json.loads(err.read())
                                if json_error:
                                        print json.dumps(json_error,sort_keys=True,indent=4, separators=(',', ': '))
                        except ValueError:
                                pass
                finally:
                        if f:  f.close()
        else:
                print('\nSkipping the configuration push to the firewall')
def main(argv):
        parser = argparse.ArgumentParser(description='FW Management')
        parser.add_argument('-c', '--config', dest='config', type=str, required=False,help='configuration file')
        parser.add_argument('-a', '--action', dest='action', type=str, required=True,help='action to perform [enable|disable]')
        args = parser.parse_args()
        if args.action=='read':
                read_data(1)
        elif args.action=='search':
                search_data()
        elif args.action=='write':
                make_data()
        if change==1:
                choice=raw_input('\nThe device configuration has been changed by the script. Would you want to save the device config to NVRAM?[Yes]').lower()
                if choice=='':
                        choice='yes'
                if choice=='yes':
                        json_data={}
                        json_data['commands']=["write memory"]
                        write_data(json_data,server+'/api/cli')
                else:
                        print('\nExiting the script without saving the device configuration!!!')


if __name__ == "__main__":
    main(sys.argv[1:])
