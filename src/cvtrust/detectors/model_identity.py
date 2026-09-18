"""Model identity: cryptographic substitution detection.

The most certain thing Module 2 says, and the only one whose confidence is 1.0
and means it.  Two SHA-256 digests either match or they do not; there is no
inference, no threshold and no feature space involved.

This detector is deliberately separate from behavioural comparison, because a
model may behave identically while being a different artifact — and a model may
be byte-identical while the *deployment* around it changed.  Collapsing the two
would lose the distinction that makes the report useful:

    Identity:  MISMATCH
    Structure: MATCH
    Behaviour: unchanged

is a re-serialisation.

    Identity:  MISMATCH
    Structure: MATCH
    Behaviour: 12% disagreement

is a different set of weights.  One number cannot say both.
"""

from __future__ import annotations

from ..core.evidence import (
    Category,
    ConfidenceBasis,
    Coverage,
    EvidenceItem,
    Severity,
)
from ..models.base import Capability
from ..models.manifest import compare_identity
from .base import DetectorOutput, FindingFactory, coverage_entry
from .model_base import ModelAnalysisContext

ATTACK_CLASS = "model_substitution"

#: How each identity outcome is graded.  A table rather than an if-chain,
#: because the mapping from observation to severity is a policy an analyst
#: should be able to disagree with, and it is printed in the finding.
SEVERITY_TABLE: dict[str, tuple[Severity, str]] = {
    "DIFFERENT_MODEL": (
        Severity.CRITICAL,
        "a different architecture carrying different weights is being served in "
        "place of the assured model; nothing measured about the reference "
        "applies to what is actually deployed",
    ),
    "SAME_ARCHITECTURE_DIFFERENT_WEIGHTS": (
        Severity.HIGH,
        "the artifact shares the reference architecture but not its weights, so "
        "every behavioural assurance measured on the reference has to be "
        "re-established for this artifact",
    ),
    "RESERIALISED": (
        Severity.MEDIUM,
        "the bytes differ but the graph and the weights are identical: this is a "
        "re-packaging, not a different model. It still breaks byte-level "
        "attestation and should be explained, but it is not a substitution",
    ),
    "DIFFERENT_BYTES_STRUCTURE_UNAVAILABLE": (
        Severity.HIGH,
        "the bytes differ and this format does not expose enough structure to "
        "determine whether the underlying model differs too",
    ),
}


class ModelIdentityDetector:
    """Deterministic identity comparison against a trusted reference."""

    name = "model_identity"
    version = "1.0"
    attack_classes = (ATTACK_CLASS,)
    required_capabilities: tuple[Capability, ...] = ()

    def run(self, ctx: ModelAnalysisContext) -> DetectorOutput:
        factory = FindingFactory(ctx, self.name, self.version)
        out = DetectorOutput(detector=self.name, version=self.version)
        supplied = ctx.supplied_manifest

        # Always record the artifact's own identity, even with no reference:
        # an assessment whose subject is not pinned to a digest is not evidence
        # of anything, and Module 3 will bind inference records to this value.
        out.stats = {
            "supplied_identity": supplied.identity_summary(),
            "has_reference": ctx.has_reference,
        }

        if not ctx.has_reference:
            reason = (
                "no trusted reference model was supplied, so substitution cannot "
                "be assessed: identity is a comparison, and there is nothing to "
                "compare against. The supplied artifact's digests are recorded so "
                "that a future assessment can make this comparison."
            )
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.NOT_ASSESSED,
                    detector=self.name, detector_version=self.version, reason=reason,
                    limitations=(
                        "identity assurance requires a reference obtained through a "
                        "channel independent of the one that supplied the artifact",
                    ),
                )
            )
            return out

        reference = ctx.reference_manifest
        assert reference is not None
        comparison = compare_identity(supplied, reference)
        ctx.shared["identity_comparison"] = comparison
        out.stats["identity_comparison"] = comparison

        if comparison["identity_match"]:
            out.coverage.append(
                coverage_entry(
                    ATTACK_CLASS, Coverage.SUPPORTED,
                    detector=self.name, detector_version=self.version,
                    assumptions=(
                        "the reference digest was obtained through a channel "
                        "independent of the one that supplied the artifact",
                    ),
                    limitations=(
                        "a byte match verifies that this artifact is the reference "
                        "artifact. It says nothing about whether the reference "
                        "itself is trustworthy",
                    ),
                )
            )
            out.flagged[ATTACK_CLASS] = set()
            return out

        code = str(comparison["interpretation_code"])
        severity, rationale = SEVERITY_TABLE.get(
            code, (Severity.HIGH, "the supplied artifact is not the reference artifact")
        )

        evidence = [
            EvidenceItem(
                kind="cryptographic_identity",
                statement=(
                    f"The supplied artifact's SHA-256 does not match the trusted "
                    f"reference's: {supplied.file_sha256[:16]}… vs "
                    f"{reference.file_sha256[:16]}…."
                ),
                observation={
                    "reference_sha256": reference.file_sha256,
                    "supplied_sha256": supplied.file_sha256,
                    "match": False,
                    "hash_algorithm": supplied.hash_algorithm,
                    "reference_size_bytes": reference.file_size_bytes,
                    "supplied_size_bytes": supplied.file_size_bytes,
                },
                refs=(str(ctx.supplied.path),),
            ),
            EvidenceItem(
                kind="structural_identity",
                statement=(
                    "The graph and parameter digests separate a re-serialisation "
                    "from a genuinely different model."
                ),
                observation={
                    "reference_graph_digest": comparison["reference_graph_digest"],
                    "supplied_graph_digest": comparison["supplied_graph_digest"],
                    "graph_match": comparison["graph_match"],
                    "reference_parameter_digest": comparison["reference_parameter_digest"],
                    "supplied_parameter_digest": comparison["supplied_parameter_digest"],
                    "parameter_match": comparison["parameter_match"],
                    "reference_parameter_count": comparison["reference_parameter_count"],
                    "supplied_parameter_count": comparison["supplied_parameter_count"],
                },
                refs=(),
            ),
            EvidenceItem(
                kind="identity_interpretation",
                statement=str(comparison["interpretation"]),
                observation={
                    "interpretation_code": code,
                    "severity": severity.value,
                    "severity_rationale": rationale,
                },
                refs=(),
            ),
        ]

        declared = supplied.declared_metadata
        if declared:
            # Recorded explicitly as untrusted: the substitution scenario in the
            # attack lab keeps the reference's architecture name in its
            # metadata, which is precisely why a name is never an identity.
            evidence.append(
                EvidenceItem(
                    kind="declared_metadata",
                    statement=(
                        "Metadata the artifact declares about itself, recorded for "
                        "context. It is supplied by the untrusted side and played "
                        "no part in the identity decision above."
                    ),
                    observation={
                        "declared": {k: str(v) for k, v in sorted(declared.items())},
                        "trusted": False,
                        "used_in_identity_decision": False,
                    },
                    refs=(),
                )
            )

        out.findings.append(
            factory.emit(
                attack_class=ATTACK_CLASS,
                asset=ctx.model_asset(),
                category=Category.MODEL,
                title="Supplied model differs from the trusted reference",
                severity=severity,
                confidence=1.0,
                basis=ConfidenceBasis.DETERMINISTIC,
                coverage=Coverage.SUPPORTED,
                discriminator=(code, reference.file_sha256),
                evidence=evidence,
                assumptions=(
                    "the reference digest was obtained through a channel "
                    "independent of the one that supplied the artifact under "
                    "assessment",
                    "SHA-256 is collision-resistant",
                ),
                limitations=(
                    "an identity mismatch establishes that the artifact changed. "
                    "It does not establish that the change was malicious: a "
                    "legitimate retrain, re-export or recompilation produces the "
                    "same observation",
                    "this finding says nothing about the trustworthiness of the "
                    "reference model itself",
                ),
            )
        )
        out.flagged[ATTACK_CLASS] = {supplied.model_id}
        # A deterministic detector has no ranking score; the evaluation harness
        # scores it on the flagged set alone, and 1.0 records that certainty.
        out.scores[ATTACK_CLASS] = {supplied.model_id: 1.0}
        out.coverage.append(
            coverage_entry(
                ATTACK_CLASS, Coverage.SUPPORTED,
                detector=self.name, detector_version=self.version,
                assumptions=(
                    "the reference digest is authentic",
                    "SHA-256 is collision-resistant",
                ),
                limitations=(
                    "detects that the artifact differs, not that it is malicious",
                    "cannot detect substitution of a model that was never "
                    "assured: with no reference there is nothing to compare",
                ),
            )
        )
        return out
