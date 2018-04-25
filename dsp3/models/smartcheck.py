import sys
import datetime
import urllib3
import json
import requests

class SmartCheck():

    def __init__(self, username: str, password: str, host: str, port: int = '443',
                 verify_ssl:bool = False, cacert_file:str = False):
        """

               :param username:
               :param password:
               :param host:
               :param port:
               :param verify_ssl:
               :param cacert_file: optional CA certificates to trust for certificate verification
               """

        self.headers = {'Content-Type': 'application/json'}
        self._username = username
        self._password = password
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.cacer_file = cacert_file
        self.token = None
        self.token_expires = None
        self.password_change_require = False
        urllib3.disable_warnings()

        try:
            self.session_id = self.__authenticate()
        except Exception as ex:
            print("Authentication error: ", ex)
            sys.exit()

    def __authenticate(self) -> str:
        credentials = json.dumps(dict(user=dict(userID=self._username, password=self._password)))
        url = "https://{}:{}/api/sessions".format(self.host, self.port)
        r = requests.post(url, data=credentials, verify=self.verify_ssl, headers=self.headers)
        r_json = json.loads(r.content.decode('utf-8'))
        self.token = r_json['token'] if r_json else None
        self.token_expires = datetime.datetime.strptime(r_json['expires'], '%Y-%m-%dT%H:%M:%SZ') if self.token else None
        self.password_change_require = r_json['user']['passwordChangeRequired']
        return r.content.decode('utf-8')


    def get_sessions(self):
        """
        Retrieve a list of sessions.

        :return: json object with sessions
        """
        url = "https://{}:{}/api/sessions".format(self.host, self.port)
        self.headers['Authorization'] = "Bearer %s" % self.token
        r = requests.get(url, verify=self.verify_ssl, headers=self.headers)

        return json.loads(r.content.decode('utf-8'))


    def get_users(self):
        """
        Retrieve a list of users.

        :return: json object with users
        """
        url = "https://{}:{}/api/users".format(self.host, self.port)
        self.headers['Authorization'] = "Bearer %s" % self.token
        r = requests.get(url, verify=self.verify_ssl, headers=self.headers)
        return json.loads(r.content.decode('utf-8'))