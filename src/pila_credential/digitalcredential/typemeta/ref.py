from dataclasses import dataclass


@dataclass
class Ref:
    vct: str
    integrity: str = ""
