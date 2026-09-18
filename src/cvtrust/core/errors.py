"""Exception hierarchy.

Every error raised by cvtrust derives from :class:`CvTrustError` so that the CLI
can distinguish an expected, explainable failure (bad dataset, unusable config)
from a genuine bug, which must surface with a traceback.
"""

from __future__ import annotations


class CvTrustError(Exception):
    """Base class for all expected cvtrust failures."""


class ConfigError(CvTrustError):
    """Configuration is malformed, contradictory or references missing paths."""


class CanonicalizationError(CvTrustError):
    """A value cannot be serialised into the canonical, digest-safe form."""


class AdapterError(CvTrustError):
    """A dataset adapter could not parse the input it was given."""


class DatasetError(CvTrustError):
    """The dataset is structurally unusable (empty, missing root, no samples)."""


class DetectorUnavailable(CvTrustError):
    """A detector's stated requirements are not met.

    This is *not* a bug and must never be swallowed into "zero findings": the
    caller is required to record the detector as ``NOT_ASSESSED`` with this
    exception's message as the machine-readable reason.
    """


class VerificationError(CvTrustError):
    """An integrity verification (manifest re-check, digest match) failed."""


class ProvenanceError(CvTrustError):
    """A provenance record, log or trust store is structurally unusable.

    Deliberately distinct from a *verification failure*: a record that fails
    verification is a normal, reportable outcome carrying structured evidence,
    not an exception.  This is raised only when the artifact cannot be parsed
    far enough to be verified at all, and the caller is required to report that
    as ``MALFORMED_RECORD`` rather than as an absence of findings.
    """


class KeyError_(CvTrustError):
    """A signing or verification key cannot be loaded, decoded or used."""


#: Public name for the key error.  ``KeyError`` is a builtin, and shadowing it
#: inside a package that also does dictionary lookups is a bug generator, so the
#: class is defined under a private name and exported under a qualified one.
KeyMaterialError = KeyError_
