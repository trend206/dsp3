from datetime import datetime, timezone
import json
import time

import requests

class ModifyTrustedUpdateModeRequest:

    def __init__(self, duration: int, enabled: bool):
        self.duration = duration
        self.enabled = enabled

    def to_json(self):
        return json.dumps(dict(ModifyTrustedUpdateModeRequest=dict(duration=self.duration, enabled=self.enabled)))




