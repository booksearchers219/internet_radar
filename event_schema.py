from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class RadarEvent:
    title: str
    source: str
    type: str
    severity: int
    url: str
    timestamp: str
    id: Optional[str] = None  # ✅ ADD THIS

    def to_dict(self):
        return {
            "id": self.id,  # ✅ ADD THIS
            "title": self.title,
            "source": self.source,
            "type": self.type,
            "severity": self.severity,
            "url": self.url,
            "timestamp": self.timestamp
        }