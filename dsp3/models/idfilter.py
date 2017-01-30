from suds import Client


class IDFilter():

    def __init__(self, id, operator, client):
        self.id = id
        self.operator = operator
        self.client = client

    def get_transport(self):
        idft = self.client.factory.create('IDFilterTransport')
        idft.id = self.id

        eo = self.client.factory.create('EnumOperator')
        operators = {"GREATER_THAN": eo.GREATER_THAN, "LESS_THAN": eo.LESS_THAN, "EQUAL":eo.EQUAL }

        if operators[self.operator]:
            idft.operator = operators[self.operator]
        else:
            idft.operator = eo.GREATER_THAN


        return idft
