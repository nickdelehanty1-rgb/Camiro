"""
Art. 50 EU AI Act transparency scanner.

Detects three categories of transparency gap:
  1. Chatbot / conversational AI with no AI disclosure to the user (Art. 50(1))
  2. AI-generated content (text/image/audio/video) without machine-readable marking (Art. 50(2))
  3. Emotion recognition or biometric categorisation without informing the exposed person (Art. 50(3))

Application date notes embedded in finding descriptions:
  - Art. 50(1) and 50(3): apply from 2 August 2026
  - Art. 50(2) marking for legacy systems: 2 December 2026
"""
import re
from .base import BaseScanner, ScannerFinding

_APP_DATE_50_1 = "2 August 2026"
_APP_DATE_50_2 = "2 August 2026 (legacy systems: 2 December 2026)"
_APP_DATE_50_3 = "2 August 2026"


# ── Art. 50(1) — chatbot / conversational AI disclosure ──────────────────────

_CHATBOT_PATTERNS = [
    r'\bchat(?:bot|_bot|Bot)\b',
    r'\bconversational[_\s]ai\b',
    r'\bvirtual[_\s]assistant\b',
    r'\bassistant[_\s](?:bot|agent|service)\b',
    r'class\s+\w*(?:Chat|Chatbot|Bot|Assistant|Conversational)\w*\b',
    r'def\s+\w*(?:chat|respond|reply|handle_message|process_message|send_message)\w*\s*\(',
    r'\bchat_history\b|\bconversation_history\b|\bmessage_history\b',
    r'\brole["\']:\s*["\'](?:user|assistant)["\']',   # OpenAI-style messages list
    r'\buser_message\b|\bhuman_message\b|\bhuman_turn\b',
]

_DISCLOSURE_PATTERNS = [
    # Variable/field assignments that carry disclosure state
    r'\bai[_]disclosure\s*[=:]',
    r'\bis[_]ai\s*[=:]\s*True\b',
    r'\bai[_]powered\s*[=:]\s*True\b',
    r'\bai[_]flag\s*[=:]\s*True\b',
    r'\bbot[_]disclosure\s*[=:]',
    r'\bchatbot[_]notice\s*[=:]',
    # Return structures that include disclosure
    r'"ai_disclosure"\s*:',
    r"'ai_disclosure'\s*:",
    r'"is_ai"\s*:\s*True',
    r"'is_ai'\s*:\s*True",
    r'"ai_powered"\s*:\s*True',
    r"'ai_powered'\s*:\s*True",
    # Literal disclosure strings in code (not docstrings — single-line only, bounded)
    r'^[^#"\']*"[^"\n]*\bI am an AI\b[^"\n]*"',
    r"^[^#\"']*'[^'\n]*\bI am an AI\b[^'\n]*'",
    r'^[^#"\']*"[^"\n]*\bThis is an AI\b[^"\n]*"',
    r'^[^#"\']*"[^"\n]*\bnot a human\b[^"\n]*"',
    r'^[^#"\']*"[^"\n]*\bAI assistant\b[^"\n]*"',
    r'^[^#"\']*"[^"\n]*\bautomated response\b[^"\n]*"',
]


# ── Art. 50(2) — AI-generated content marking ───────────────────────────────

_CONTENT_GEN_PATTERNS = [
    r'\bgenerate[_\s](?:image|video|audio|speech|content|text)\b',
    r'\btext[_\s]to[_\s](?:image|speech|video)\b',
    r'\bimage[_\s]generation\b|\bimage[_\s]synthesis\b',
    r'\bspeech[_\s]synthesis\b|\bsynthesize[_\s]speech\b',
    r'\bdeepfake\b|\bface[_\s]swap\b|\bvoice[_\s]clone\b',
    r'\bdall.e\b|\bstable[_\s]diffusion\b|\bmidjourney\b',
    r'\bgenai[_\s]content\b|\bai[_\s]generated[_\s](?:image|video|audio|content)\b',
    r'model\.generate\b|pipeline\.generate\b',
    r'\bsynthesize[_\s](?:audio|video|image)\b',
]

_MARKING_PATTERNS = [
    r'\bwatermark\b|\bwatermarking\b',
    r'\bcontent[_\s]credentials\b|\bc2pa\b',
    r'\bai[_\s]label\b|\bai[_\s]marking\b|\bai[_\s]tag\b',
    r'\bmachine[_\s]readable[_\s]mark\b',
    r'\bprovenance\b|\bcontent[_\s]provenance\b',
    r'\bai[_\s]generated[_\s]metadata\b',
    r'\bdisclos(?:e|ure)[^"\']{0,60}(?:ai.generated|synthetic|generated)\b',
]


# ── Art. 50(3) — emotion recognition / biometric categorisation ─────────────

_EMOTION_BIOMETRIC_PATTERNS = [
    r'\bemotion[_\s](?:recognition|detection|analysis|classifier)\b',
    r'\bdetect[_\s]emotion\b|\banalyse[_\s]emotion\b|\bclassify[_\s]emotion\b',
    r'\baffect[_\s]recognition\b|\baffective[_\s]computing\b',
    r'\bsentiment[_\s](?:from[_\s](?:face|voice|video|audio|image))\b',
    r'\bfacial[_\s](?:expression|affect|emotion)\b',
    r'\bbiometric[_\s]categori[sz]ation\b|\bbiometric[_\s]classif\b',
    r'class\s+\w*(?:EmotionRecog|AffectDetect|BiometricCateg)\w*\b',
    r'def\s+\w*(?:detect_emotion|recognize_emotion|analyse_emotion|categorise_biometric)\w*\s*\(',
]

_PERSON_NOTIFY_PATTERNS = [
    r'\bnotif(?:y|ication)[^"\']{0,60}\b(?:emotion|biometric|recognition)\b',
    r'\binform[^"\']{0,60}\b(?:emotion|biometric|recognition)\b',
    r'\bemotion[_\s](?:disclosure|notice|consent)\b',
    r'\biometric[_\s](?:notice|disclosure|consent|inform)\b',
    r'\baffect[_\s](?:disclosure|notice)\b',
]


class TransparencyScanner(BaseScanner):
    """Detects EU AI Act Art. 50 transparency gaps."""

    name = "transparency"

    def scan(self, code: str, filename: str = "") -> list[ScannerFinding]:
        findings = []
        findings.extend(self._check_chatbot_disclosure(code, filename))
        findings.extend(self._check_content_marking(code, filename))
        findings.extend(self._check_emotion_biometric(code, filename))
        return findings

    # ── Art. 50(1) ────────────────────────────────────────────────────────────

    def _check_chatbot_disclosure(self, code: str, filename: str) -> list[ScannerFinding]:
        has_chatbot = any(
            re.search(p, code, re.IGNORECASE) for p in _CHATBOT_PATTERNS
        )
        if not has_chatbot:
            return []

        has_disclosure = any(
            re.search(p, code, re.IGNORECASE) for p in _DISCLOSURE_PATTERNS
        )

        if not has_disclosure:
            # Find first matching line for evidence
            line_num, line_text = self._first_match(code, _CHATBOT_PATTERNS)
            return [ScannerFinding(
                scanner_name=self.name,
                finding_type="missing_ai_disclosure",
                title="Chatbot / conversational AI has no AI disclosure (Art. 50(1))",
                description=(
                    "Code implements a chatbot or conversational AI that interacts with "
                    "natural persons but contains no disclosure that the user is interacting "
                    "with an AI. EU AI Act Art. 50(1) requires a clear, prominent disclosure "
                    f"prior to and during every interaction. Applies from {_APP_DATE_50_1}. "
                    "Without disclosure, users cannot exercise their right to know they are "
                    "not speaking with a human."
                ),
                confidence=0.85,
                file_path=filename,
                line_start=line_num,
                evidence_excerpt=self._excerpt(line_text),
                tags=["transparency", "AI_ACT_ART50", "chatbot", "disclosure_missing"],
                suggested_node_type="processing_activity",
                metadata={
                    "obligation": "AI_ACT_ART50_1_CHATBOT_DISCLOSURE",
                    "application_date": "2026-08-02",
                }
            )]

        return []

    # ── Art. 50(2) ────────────────────────────────────────────────────────────

    def _check_content_marking(self, code: str, filename: str) -> list[ScannerFinding]:
        has_gen = any(
            re.search(p, code, re.IGNORECASE) for p in _CONTENT_GEN_PATTERNS
        )
        if not has_gen:
            return []

        has_marking = any(
            re.search(p, code, re.IGNORECASE) for p in _MARKING_PATTERNS
        )

        if not has_marking:
            line_num, line_text = self._first_match(code, _CONTENT_GEN_PATTERNS)
            return [ScannerFinding(
                scanner_name=self.name,
                finding_type="missing_content_marking",
                title="AI-generated content produced without machine-readable marking (Art. 50(2))",
                description=(
                    "Code generates AI-created content (image, audio, video or text) without "
                    "any machine-readable marking or watermarking to indicate it is AI-generated. "
                    "EU AI Act Art. 50(2) requires machine-readable marking of AI-generated outputs. "
                    f"Applies from {_APP_DATE_50_2}. "
                    "Synthetic or manipulated content depicting real persons must also carry "
                    "a visible disclosure."
                ),
                confidence=0.80,
                file_path=filename,
                line_start=line_num,
                evidence_excerpt=self._excerpt(line_text),
                tags=["transparency", "AI_ACT_ART50", "content_generation", "marking_missing"],
                suggested_node_type="processing_activity",
                metadata={
                    "obligation": "AI_ACT_ART50_2_CONTENT_MARKING",
                    "application_date": "2026-08-02",
                    "legacy_application_date": "2026-12-02",
                }
            )]

        return []

    # ── Art. 50(3) ────────────────────────────────────────────────────────────

    def _check_emotion_biometric(self, code: str, filename: str) -> list[ScannerFinding]:
        has_emotion = any(
            re.search(p, code, re.IGNORECASE) for p in _EMOTION_BIOMETRIC_PATTERNS
        )
        if not has_emotion:
            return []

        has_notify = any(
            re.search(p, code, re.IGNORECASE) for p in _PERSON_NOTIFY_PATTERNS
        )

        if not has_notify:
            line_num, line_text = self._first_match(code, _EMOTION_BIOMETRIC_PATTERNS)
            return [ScannerFinding(
                scanner_name=self.name,
                finding_type="missing_emotion_disclosure",
                title="Emotion recognition / biometric categorisation with no person notification (Art. 50(3))",
                description=(
                    "Code performs emotion recognition or biometric categorisation of natural persons "
                    "but no notification or disclosure to the exposed person was detected. "
                    "EU AI Act Art. 50(3) requires deployers to inform natural persons that an "
                    "emotion recognition or biometric categorisation system is operating on them. "
                    f"Applies from {_APP_DATE_50_3}."
                ),
                confidence=0.85,
                file_path=filename,
                line_start=line_num,
                evidence_excerpt=self._excerpt(line_text),
                tags=["transparency", "AI_ACT_ART50", "emotion_recognition", "biometric", "disclosure_missing"],
                suggested_node_type="processing_activity",
                metadata={
                    "obligation": "AI_ACT_ART50_3_EMOTION_BIOMETRIC",
                    "application_date": "2026-08-02",
                }
            )]

        return []

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _first_match(self, code: str, patterns: list[str]) -> tuple[int, str]:
        for p in patterns:
            matches = self._find_lines_matching(code, re.compile(p, re.IGNORECASE))
            if matches:
                return matches[0]
        return (0, "")
