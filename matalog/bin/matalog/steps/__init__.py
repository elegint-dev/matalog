"""The profiler steps. Each module holds one step; all_steps() returns them in order."""
from .s1_enumerate_sources import EnumerateSources
from .s2_enumerate_strata import EnumerateStrata
from .s3_discover import Discover
from .s4_profile import Profile
from .s5_read_config import ReadConfig
from .s6_parse_usage import ParseUsage
from .s7_classify import Classify
from .s8_derive_meaning import DeriveMeaning
from .s10_commit import Commit

STEP_CLASSES = (EnumerateSources, EnumerateStrata, Discover, Profile, ReadConfig, ParseUsage, Classify, DeriveMeaning, Commit)


def all_steps():
    """Fresh step instances in contract order, S1 to S8 then S10."""
    return [cls() for cls in STEP_CLASSES]
