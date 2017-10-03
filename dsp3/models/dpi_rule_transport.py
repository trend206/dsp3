class DPIRuleTransport:

    def __init__(self, suds_client, name, applicationTypeID, eventOnPacketDrop, eventOnPacketModify, templateType, patternAction,
                patternIf, priority, signatureAction, severity, ruleXML, rule_id=   None, detectOnly=False, disableEvent=False,
                 ignoreRecommendations=False, includePacketData=False, patternCaseSensitive=False, raiseAlert=False,
                 signatureCaseSensitive=False, cvssScore=0, authoritative = False):

        self.client = suds_client
        self.name = name
        self.applicationTypeID = applicationTypeID
        self.eventOnPacketDrop = eventOnPacketDrop
        self.eventOnPacketModify = eventOnPacketModify
        self.templateType = templateType
        self.patternAction = patternAction
        self.patternIf = patternIf
        self.priority = priority
        self.signatureAction = signatureAction
        self.severity = severity
        self.ruleXML = ruleXML
        self.detectOnly = detectOnly
        self.disableEvent = disableEvent
        self.ignoreRecommendations = ignoreRecommendations
        self.includePacketData = includePacketData
        self.patternCaseSensitive = patternCaseSensitive
        self.signatureCaseSensitive = signatureCaseSensitive
        self.cvssScore = cvssScore
        self.authoritative = authoritative
        self.raiseAlert = raiseAlert

        if rule_id is not None:
            self.ID = rule_id

    def get_transport(self):
        dpirt = self.client.factory.create('DPIRuleTransport')
        dpirt.name = self.name
        dpirt.applicationTypeID = self.applicationTypeID
        dpirt.eventOnPacketDrop = self.eventOnPacketDrop
        dpirt.eventOnPacketModify = self.eventOnPacketModify
        dpirt.templateType = self.templateType
        dpirt.patternAction = self.patternAction
        dpirt.patternIf = self.patternIf
        dpirt.priority = self.priority
        dpirt.signatureAction = self.signatureAction
        dpirt.severity = self.severity
        dpirt.ruleXML = self.ruleXML
        dpirt.detectOnly = self.detectOnly
        dpirt.disableEvent = self.disableEvent
        dpirt.ignoreRecommendations = self.ignoreRecommendations
        dpirt.includePacketData = self.includePacketData
        dpirt.patternCaseSensitive = self.patternCaseSensitive
        dpirt.raiseAlert = self.raiseAlert
        dpirt.signatureCaseSensitive = self.signatureCaseSensitive
        dpirt.cvssScore = self.cvssScore
        dpirt.authoritative = self.authoritative

        if hasattr(self, 'ID'):
            dpirt.ID = self.ID

        return dpirt