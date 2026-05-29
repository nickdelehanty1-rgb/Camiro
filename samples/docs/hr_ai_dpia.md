# Data Protection Impact Assessment
## AI-Powered Candidate Screening System — AcmeHire Ltd

**Status:** DRAFT  
**Version:** 0.2  
**Date:** March 2024  
**Prepared by:** HR Operations  
**Reviewed by:** (Pending legal review)

---

## 1. Description of Processing

AcmeHire uses an AI-powered system to screen and score job applications.
The system analyses CV text, cover letter content and application responses
to generate a candidate suitability score from 1 to 10.

Candidates scoring below a defined threshold may be removed from the active
pipeline. Candidates scoring above a high threshold may be advanced to the
next stage.

**System components:**
- Application intake form (web)
- Candidate database (PostgreSQL)
- Scoring engine (third-party AI API)

## 2. Purpose and Necessity

**Purpose:** To improve the efficiency and consistency of initial candidate screening.

**Necessity:** The volume of applications received exceeds the capacity for manual
review at the initial screening stage. Automated pre-screening reduces time-to-hire
and aims to apply consistent criteria.

**Proportionality:** The score is one input into the hiring process.
*(Note: final decision process not yet documented.)*

## 3. Data Involved

| Category | Fields |
|----------|--------|
| Identity | Name, email address |
| Contact | Phone number, postal address |
| Professional | CV, cover letter, work history, education |
| Assessment | AI-generated suitability score |

## 4. Risk Assessment

| Risk | Likelihood | Severity | Notes |
|------|-----------|----------|-------|
| Algorithmic bias against protected groups | High | High | No bias audit conducted yet |
| Data breach via AI API | Medium | High | API key management to be reviewed |
| Score manipulation via adversarial inputs | Low | Medium | |
| Excessive data retention | Medium | Medium | Deletion schedule not yet implemented |

## 5. Mitigation Measures

- Periodic bias audits to be scheduled (frequency TBD)
- Data encrypted at rest and in transit via TLS
- Access to candidate scores restricted to HR team

## 6. Consultation

DPO has been notified of this processing activity.
Full DPO consultation and sign-off is pending.
Legal review of AI Act classification has not yet been completed.

## 7. Residual Risk

Overall residual risk is assessed as **Medium-High** pending completion of
bias audit and legal classification review.

---

*This DPIA is a draft and requires DPO sign-off before the system goes live.*
