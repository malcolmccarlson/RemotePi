import oauth2
import requests
import json
from configparser import ConfigParser


Config = ConfigParser()
Config.read('config.ini')


myappkey = Config.get('Authentication', 'APP_KEY')
myappsecret = Config.get('Authentication', 'APP_SECRET')
mypassword = Config.get('AccountLogin', 'MYPASSWORD')
myemail = Config.get('AccountLogin', 'EMAIL')
myremoturl = Config.get('URLs', 'REMOTE_URL')
myurlfortoken = Config.get('URLs', 'URLFORTOKEN')
myredirecturi = Config.get('URLs', 'REDIRECTURI')
myremoteother = Config.get('URLs', 'REMOTE_OTHER')


def getcayennetoken():
    payload = {"grant_type": "password",
               "email": myemail,
               "password": mypassword
               }
    try:
        r = requests.post(myurlfortoken, data=json.dumps(payload))
        r.raise_for_status()
        mydict = json.loads(r.content)
        atoken = mydict['access_token']
        rtoken = mydict['refresh_token']
        return atoken, rtoken
    except requests.exceptions.HTTPError as err:
        print(err)


def getcayenneapps():
    atoken, rtoken = getcayennetoken()
    payload = {'Authorization': "Bearer %s" % atoken,
               'X-API-Version': '1.0'}
    try:
        r = requests.get(myremoturl+'/applications', headers=payload)
        r.raise_for_status()
        mylist = json.loads(r.content)
        listtodict = mylist[0]
        appid = listtodict['id']
        appsecret = listtodict['secret']
        return appid, appsecret
    except requests.exceptions.HTTPError as err:
        print(err)

def recursive_items(dictionary):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield (key, value)
            yield from recursive_items(value)
        else:
            yield (key, value)


def getthings():
    atoken, rtoken = getcayennetoken()
    payload = {'Authorization': "Bearer %s" % atoken,
               'X-API-Version': '1.0'}
    try:
        r = requests.get(myremoteother+'/things', headers=payload)
        r.raise_for_status()
        mylist = json.loads(r.content)
        print(mylist)
    except requests.exceptions.HTTPError as err:
        print(err)


def getjobs():
    atoken, rtoken = getcayennetoken()
    payload = {'Authorization': "Bearer %s" % atoken,
               'X-API-Version': '1.0'}
    try:
        r = requests.get(myremoteother+'/jobs', headers=payload)
        r.raise_for_status()
        mylist = json.loads(r.content)
        if mylist is None:
            print(True)
    except requests.exceptions.HTTPError as err:
        print(err)


def createjob():
    pass


if __name__ == '__main__':
    myreturn = getthings()
    print(myreturn)
