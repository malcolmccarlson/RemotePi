import oauth2
import requests
import json
from configparser import ConfigParser


Config = ConfigParser()
Config.read('cayenneconfig.ini')


myappkey = Config.get('Authentication', 'APP_KEY')
myappsecret = Config.get('Authentication', 'APP_SECRET')
mypassword = Config.get('AccountLogin', 'MYPASSWORD')
myemail = Config.get('AccountLogin', 'EMAIL')
myremoturl = Config.get('URLs', 'REMOTE_URL')
myurlfortoken = Config.get('URLs', 'URLFORTOKEN')
myredirecturi = Config.get('URLs', 'REDIRECTURI')


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


if __name__ == '__main__':
    getcayenneapps()
