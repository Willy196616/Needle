"""
Attack Registry - Maps attack names to their classes.
"""

from attacks.extraction import ExtractionAttack
from attacks.injection import PromptInjectionAttack
from attacks.jailbreak import JailbreakAttack
from attacks.dos_and_output import DoSAttack, OutputManipulationAttack

ATTACK_MODULES = {
    "extraction": ExtractionAttack,
    "injection": PromptInjectionAttack,
    "jailbreak": JailbreakAttack,
    "dos": DoSAttack,
    "output": OutputManipulationAttack,
}

ALL_ATTACKS = list(ATTACK_MODULES.keys())
