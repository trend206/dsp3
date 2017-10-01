class DPIRuleTransport:

    def __init__(self, suds_client, name, applicationTypeID, eventOnPacketDrop, eventOnPacketModify, templateType, patternAction,
                patternIf, priority, signatureAction, severity, ruleXML, detectOnly=False, disableEvent=False,
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

    def get_transport(self):
        dpirt = self.client.factory.create('DPIRuleTransport')

        #edtt = self.client.factory.create('EnumDPIRuleTemplateType')
        #enra = self.client.factory.create('EnumDPIRuleAction')
        #enri = self.client.factory.create('EnumDPIRuleIf')
        #edrp = self.client.factory.create('EnumDPIRulePriority')
        #enrs = self.client.factory.create('EnumDPIRuleSeverity')


        dpirt.name = self.name
        dpirt.applicationTypeID = self.applicationTypeID
        dpirt.eventOnPacketDrop = self.eventOnPacketDrop
        dpirt.eventOnPacketModify = self.eventOnPacketModify
        #dpirt.templateType = edtt.CUSTOM_XML
        dpirt.templateType = self.templateType
        #dpirt.patternAction = enra.DROP_CLOSE
        dpirt.patternAction = self.patternAction
        #dpirt.patternIf = enri.ANY_PATTERNS_FOUND
        dpirt.patternIf = self.patternIf
        #dpirt.priority = edrp.NORMAL
        dpirt.priority = self.priority
        #dpirt.signatureAction = enra.DROP_CLOSE
        dpirt.signatureAction = self.signatureAction
        #dpirt.severity = enrs.MEDIUM
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

        return dpirt