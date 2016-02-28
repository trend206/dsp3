from suds import Client

import config
from utilities import iplists as ipl_utils
from utilities import portlist_utils as pl_utils
from utilities.sslcontext import create_ssl_context, HTTPSTransport


class Manager:


    def __init__(self, username, password, verify_ssl=False):

        kwargs = {}
        self._username = username
        self._password = password
        self.port = config.dsm_port
        url = "{}:{}/{}".format(config.base_path, self.port, config.soap_api_wsdl)
        print(url)
        if verify_ssl == False:
            sslContext = create_ssl_context(False, None, None)
            kwargs['transport'] = HTTPSTransport(sslContext)

        self.client = Client(url, **kwargs)
        self.session_id = self.__authenticate()




    def __authenticate(self):
        return self.client.service.authenticate(username=self._username, password=self._password)


    def get_api_version(self):
        return self.client.service.getApiVersion()


    def get_port_lists_all(self):
        port_lists = self.client.service.portListRetrieveAll(sID=self.session_id)
        return pl_utils.parse_port_lists(port_lists)


    def get_ip_lists_all(self):
        ip_lists =  self.client.service.IPListRetrieveAll(sID=self.session_id)
        return ipl_utils.parse_ip_lists(ip_lists)

    def save_ip_list(self, ip_list):
        iplto = ipl_utils.convert_to_tansport_ip_list(ip_list, self.client) #return IPListTransport object
        new_iplto = self.client.service.IPListSave(ipl=iplto, sID=self.session_id)
        if new_iplto:
            return "IP List saved successfully"
        else:
            return "There was a problem"

    def delete_ip_list(self, ids):
        """
            Deletes the ip_list with the give id.

        Parameters
        ----------
        ids (string): The id(s) of the ip_list(s) to delete as a string.
                      For a single id use a string and a list of string ids for multiple deletions

        Returns
        -------
        nothing
        """

        self.client.service.IPListDelete(sID=self.session_id, ids=ids)

    def end_session(self):
        self.client.service.endSession(sID=self.session_id)

