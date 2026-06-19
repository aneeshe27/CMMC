# NexGen CMMC Level 2 Technical Demo Script

Purpose: technical product walkthrough for the new demo app. This script shows
the product working, detects drift through injects, explains remediation and
approval, and positions NexGen as an advancement beyond manual GRC workflows and
LLM-only compliance tools.

Estimated length: 4 to 6 minutes.

## Opening

**On screen:** Open the Streamlit app.

**Say:**

Hi, I’m Aneesh. This is the NexGen CMMC Level 2 verification demo.

The problem we’re solving is that CMMC evidence is usually reviewed manually, periodically, and often after the environment has already changed. NexGen turns that into an objective-level drift detector.

For this walkthrough, I’ll show one Level 2 control in depth: AC.L2-3.1.1, Authorized Access Control. In simple terms, this control asks whether access to CUI is limited to
authorized users, authorized processes acting on behalf of users, and authorized
devices.

The key point is that we are not just showing a checklist. We are showing a
working verifier that reads evidence, maps it to the NIST control objectives, finds
the exact evidence that caused the issue, and proposes governed remediation
actions that can be re-verified.

## What The Product Is Verifying

**On screen:** Point to the header, proof cards, and evidence stack selector.

**Say:**

For this demo, the evidence packet represents a contractor environment. The
Microsoft packet includes Entra ID users and groups, SharePoint permissions,
Intune device posture, authorized devices, service principals, authorized
processes, and access events.


The important thing is that the compliance decision is deterministic. NexGen uses the given API's to verify the user's backend with NIST standards
AI is not deciding whether the control passed or failed. The algorithm does
that. AI is used after the deterministic finding to explain the issue and help a
human operator understand the remediation path.

## Start Clean: Run NCAT

**On screen:** Select `Microsoft: Entra + SharePoint + Intune`, then click
`Run NCAT`.

**Say:**

I will start with the Microsoft evidence packet and run NCAT.

But as you can see, we're also capable of assessing different stacks thanks to our normalization engine, so we are able to take you know, different architectures, and different technology stacks that users may have, and we normalize it to a format that our compliance engine can process.

Here this initial packet I made sure that everything was compliant.

We also see the time to findings as well and since this is deterministic, and algorithmic, compliance can be determined very quickly.

## Inject 1: Unauthorized User Drift

**On screen:** Click `Inject User`.

**Say before clicking:**

Now I will simulate a common real-world drift event. Someone adds an external
guest user, Grace Partner, to a group that has access to the CUI resource.

In production, this could happen through an identity provider or admin console.
For the demo, the app injects that drift into the runtime evidence packet so we
can show the verifier catching it.

**After clicking:**

The result changed from `READY` to `ACTION REQUIRED`.

NexGen expanded the group permission into effective user access and detected
that Grace, an external guest, now reaches the CUI resource through the
authorized group.

Notice that the tool does not just say "failed." It identifies the failed
assessment objective: access is no longer limited to authorized users.

## Show Findings And Remediation

**On screen:** Click `Findings`, then `Remediation`.

**Say:**

In the Findings tab, the issue is evidence-linked. The finding points back to
the access path that caused the failure.

In the Remediation tab, the system gives a human-approved candidate action tied
to the exact offending evidence. This is not an automatic blind change. It is an
approval-gated recommendation.

The operator can approve, reject, or create a ticket. That is important because
in a real environment, the system should not silently modify production access.
It should make the correct action easy to understand and easy to govern.

If the AI remediation is enabled, the LLM can explain the deterministic finding
in plain language. But again, the LLM is not making the compliance decision. It
is interpreting a finding that the verifier already proved.

## Approve The User Fix

**On screen:** Click `Approve`.

**Say:**

I will approve the remediation.

The runtime evidence packet is updated by removing the injected guest
membership, and the verifier reruns against the updated evidence.

Now the control returns to `READY`.

That is the verification loop: identify the offending evidence, explain the
issue, present an approval-gated fix, update the runtime evidence, and prove the
control is back to a passing state.

## Inject 2: Unauthorized Device Drift

**On screen:** Click `Inject Device`.

**Say before clicking:**

Now I will show a different root cause: device drift.

This simulates a device authorization-policy mismatch. The user may be valid,
but the device is not approved for CUI access.

**After clicking:**

Again, the result changes to `ACTION REQUIRED`, but the failed objective is
different. This time, access is no longer limited to authorized devices.

This matters because real environments rarely fail for only one reason. A useful
system must separate identity issues from device issues from process issues, and
give the operator the right remediation path for each one.

## Show Device Remediation

**On screen:** Click `Remediation`.

**Say:**

Here the candidate action is different. The app explains that the device may
need to be blocked from CUI access or moved through a device authorization
workflow.

The remediation includes a candidate API-style action and the required approval
roles. This makes the output usable for an IT or security operator, not just a
compliance analyst.

If the operator rejects the action, the evidence stays unchanged and the finding
remains. If they ticket it, the issue is recorded for follow-up. If they approve
it, the runtime packet is repaired and the verifier can prove whether the
control returned to `MET`.

**On screen:** Click `Approve`.

**Say:**

I will approve this device remediation. The runtime packet updates, the score
returns to `READY`, and the objective status returns to six out of six.

## Optional Cross-Stack Moment

**On screen:** In the sidebar, choose `Okta + Box + Jamf`, then click
`Run NCAT`.

**Say:**

One limitation of many compliance demos is that they only work for one vendor
stack. Here, the same verifier pattern works against a different raw evidence
shape.

This packet uses Okta-style identity data, Box collaboration permissions, and
Jamf device inventory. The raw files are nested API-style JSON instead of flat
Microsoft CSV exports.

NexGen normalizes both stacks into the same internal evidence model: users,
groups, memberships, resources, permissions, devices, authorized devices,
processes, authorized processes, and access events.

That means the control logic does not have to be rewritten for every customer
toolchain. The adapter changes, but the objective test remains consistent.

**Optional action:** Click `Inject User` or `Inject Device` again.

**Say:**

The same drift story works here as well. An Okta guest added to a CUI-authorized
group or an unmanaged Jamf device accessing a Box folder produces a deterministic
finding, a candidate action, and an approval path.

## How This Advances The State Of The Art

**On screen:** Return to the dashboard overview or roadmap.

**Say:**

This is where NexGen differs from traditional compliance tooling.

Many GRC systems are very good at organizing controls, tasks, questionnaires,
and evidence. Some also provide continuous scoring or continuous controls
monitoring. But the hard part for an operator is often the last mile: which
specific evidence item caused the control to fail, what exact action would
restore the control, and can the system prove the fix worked after the change?

LLM-only compliance tools can summarize and draft quickly, but they create trust
issues if the model is deciding compliance from ambiguous evidence.

NexGen takes a different approach. The compliance decision is deterministic,
explainable, and evidence-linked. The AI layer is used only after that, to make
the finding understandable and actionable.

The defensible differentiators are:

3. Multi-stack normalization across Microsoft and non-Microsoft environments.
4. Human-approved remediation that translates a compliance failure into an IT
   action.

So the system is not just helping a contractor prepare for an assessment once.
It helps them keep their environment inside CMMC bounds as users, groups,
devices, applications, and SaaS permissions change, and it gives them a way to
prove that the corrective action actually restored the control.

## Closing

**On screen:** Show `Evidence & exports`, downloads, scorecard, and report.

**Say:**

To close, this demo shows one Level 2 control in depth, not full Level 2
coverage. But the pattern is the important part.

From a customer-provided evidence packet or future API connection, NexGen
normalizes the evidence, runs deterministic objective checks, identifies the
offending evidence, produces a scorecard and report, and gives the operator
clear remediation options.

The impact is time, cost, and risk reduction. Instead of waiting for periodic
manual review, contractors can verify critical CUI access controls quickly,
using evidence-linked findings and measurable time-to-finding.

As future work, we want the remediation layer to offer both directions. One path
is the deterministic corrective action that restores compliance immediately:
for example, remove Grace's access from the CUI resource because she is not
authorized today. That is the almost guaranteed compliance-restoring action.

The other path is an assisted, governed workflow for when Grace's access is
actually intended. In that case, the system should help the IT operator start
the process to authorize her properly. The operator could prompt the tool in
plain English, and the tool would help document the business justification,
collect the required approval, identify the right identity or policy records to
update, and file or update a ticket for follow-up.

Same goal in both directions: every CUI access change becomes a deliberate,
recorded decision rather than silent drift. The nontechnical operator should not
have to reverse-engineer the CMMC requirement or the evidence packet. The app
should make the compliant path obvious, whether the right answer is to remove
access or formally approve it.

That is the product direction: from evidence packet, to finding, to
human-approved action, to verified recovery.
