class Config:

    def __init__(self, host, port, soap_api_wsdl='webservice/Manager?WSDL'):
        self.host = host
        self.port = port
        self.soap_api_wsdl = soap_api_wsdl

    def soap_url(self):
        return "https://{}:{}/{}".format(self.host, self.port, self.soap_api_wsdl)

    def rest_url(self):
        return "https://{}:{}/rest/".format(self.host, self.port)

