# Sentinel â€” Phase 4 Technical Record
## n8n Automation Foundation

**Project:** Sentinel
**Phase:** 4 â€” Automation Foundation with n8n
**Status:** âœ… Complete
**Completed:** September 2026

---

## 1. Objective

Phase 4 introduced Sentinel's first automation layer using n8n.

The goal was to build the automation foundation first using controlled test payloads before connecting the real Sentinel FastAPI backend.

Phase 4 established a workflow that can:

- receive Sentinel-style detection data through a webhook
- inspect JSON input
- evaluate whether the event represents an attack
- route ATTACK and BENIGN traffic into different branches
- prepare structured results for both branches
- return a JSON response to the caller
- run through a published production webhook

Final automation architecture:

```text
Detection JSON
      â†“
n8n Webhook
      â†“
IF attack?
   â†™        â†˜
 TRUE      FALSE
  â†“          â†“
Prepare      Prepare
Attack       Benign
Alert        Result
  â†“          â†“
Respond      Respond
to Webhook   to Webhook
```

---

## 2. Starting Point

At the beginning of Phase 4, Sentinel already had:

- a trained XGBoost intrusion-detection model
- a FastAPI backend
- `POST /predict`
- PostgreSQL persistence
- a `detections` table
- detection history endpoints
- attack/benign prediction data available as structured JSON

The next goal was to learn how an external automation engine could react to those detection results.

---

## 3. n8n Installation and Local Setup

n8n was installed locally using Node.js and npm.

The service was started from PowerShell with:

```powershell
n8n
```

The local n8n interface was available at:

```text
http://localhost:5678
```

A local owner account was created during first startup.

For Phase 4 testing, only n8n needed to be running. FastAPI and PostgreSQL were not required yet because test payloads were sent manually.

---

## 4. Workflow Creation

A new workflow was created:

```text
Sentinel Detection Automation
```

The workflow was built manually to understand each automation concept directly.

---

## 5. Webhook Trigger

The first node was a Webhook node.

Configuration:

```text
HTTP Method: POST
Path: sentinel-detection
```

During testing, n8n generated:

```text
http://localhost:5678/webhook-test/sentinel-detection
```

The webhook acts as the automation trigger:

```text
External System
      â†“
POST JSON
      â†“
n8n Webhook
      â†“
Workflow Starts
```

---

## 6. First Test Payload

A fake Sentinel detection was sent from PowerShell.

Example ATTACK payload:

```json
{
  "detection_id": 15,
  "prediction": "ATTACK",
  "attack": true,
  "confidence": 0.987,
  "model": "XGBoost"
}
```

The webhook received the JSON successfully.

n8n wrapped the incoming request data under:

```text
body
```

Important values were accessed using expressions such as:

```text
{{ $json.body.attack }}
{{ $json.body.detection_id }}
{{ $json.body.confidence }}
{{ $json.body.model }}
```

---

## 7. IF Node

An IF node was added after the Webhook.

Condition:

```text
{{ $json.body.attack }}
```

Operator:

```text
is true
```

Branches:

```text
TRUE  â†’ ATTACK
FALSE â†’ BENIGN
```

This became Sentinel's first conditional automation decision.

---

## 8. Boolean Type Issue

The IF node initially treated the attack value as a string rather than a Boolean.

The issue was fixed by using only the direct expression:

```text
{{ $json.body.attack }}
```

in Expression mode.

After that, n8n correctly routed `true` to the ATTACK branch and `false` to the BENIGN branch.

---

## 9. ATTACK Branch

The TRUE branch was connected to an Edit Fields node renamed:

```text
Prepare Attack Alert
```

Configured fields:

```text
status
String
CRITICAL
```

```text
message
String
Sentinel detected malicious network traffic
```

```text
detection_id
Number
{{ $json.body.detection_id }}
```

```text
model
String
{{ $json.body.model }}
```

```text
confidence
Number
{{ $json.body.confidence }}
```

Successful ATTACK output:

```json
{
  "status": "CRITICAL",
  "message": "Sentinel detected malicious network traffic",
  "detection_id": 15,
  "model": "XGBoost",
  "confidence": 0.987
}
```

---

## 10. BENIGN Branch

The FALSE branch was connected to another Edit Fields node renamed:

```text
Prepare Benign Result
```

Configured fields:

```text
status
String
SAFE
```

```text
message
String
Sentinel classified traffic as benign
```

```text
detection_id
Number
{{ $json.body.detection_id }}
```

```text
model
String
{{ $json.body.model }}
```

```text
confidence
Number
{{ $json.body.confidence }}
```

Successful BENIGN output:

```json
{
  "status": "SAFE",
  "message": "Sentinel classified traffic as benign",
  "detection_id": 16,
  "model": "XGBoost",
  "confidence": 0.996
}
```

---

## 11. Test Mode Behavior

The test webhook:

```text
/webhook-test/sentinel-detection
```

only remained registered while n8n was actively listening.

During development, this required:

```text
Listen for test event
```

or:

```text
Execute workflow
```

before sending the POST request.

Without an active test listener, n8n returned a 404 indicating that the test webhook was not registered.

---

## 12. Respond to Webhook Nodes

To send the final automation result back to the caller, the Webhook node was changed to respond using:

```text
Respond to Webhook Node
```

A Respond to Webhook node was added after each branch:

```text
TRUE
 â†“
Prepare Attack Alert
 â†“
Respond to Webhook (Attack)
```

and:

```text
FALSE
 â†“
Prepare Benign Result
 â†“
Respond to Webhook (Benign)
```

Both response nodes returned the first incoming item.

---

## 13. Full Workflow

The complete Phase 4 workflow became:

```text
                     Webhook
                        â†“
                     IF attack?
                  â†™             â†˜
               TRUE             FALSE
                â†“                 â†“
       Prepare Attack      Prepare Benign
           Alert               Result
                â†“                 â†“
       Respond to          Respond to
       Webhook             Webhook
       (Attack)            (Benign)
```

---

## 14. BENIGN End-to-End Test

A BENIGN request was sent from PowerShell:

```powershell
$body = @{
    detection_id = 16
    prediction = "BENIGN"
    attack = $false
    confidence = 0.996
    model = "XGBoost"
} | ConvertTo-Json
```

The workflow returned:

```text
status       : SAFE
message      : Sentinel classified traffic as benign
detection_id : 16
model        : XGBoost
confidence   : 0.996
```

This confirmed the FALSE branch worked correctly.

---

## 15. ATTACK End-to-End Test

An ATTACK request was sent:

```powershell
$body = @{
    detection_id = 16
    prediction = "ATTACK"
    attack = $true
    confidence = 0.996
    model = "XGBoost"
} | ConvertTo-Json
```

The workflow returned:

```text
status       : CRITICAL
message      : Sentinel detected malicious network traffic
detection_id : 16
model        : XGBoost
confidence   : 0.996
```

This confirmed the TRUE branch worked correctly.

---

## 16. Workflow Publishing

After both branches were validated, the workflow was published.

A meaningful published version name was used:

```text
Phase 4 - Initial Detection Automation
```

Publishing activated the workflow's production webhook.

---

## 17. Production Webhook

The production webhook became:

```text
http://localhost:5678/webhook/sentinel-detection
```

Unlike the test webhook, the production webhook does not require clicking:

```text
Listen for test event
```

or:

```text
Execute workflow
```

before every request.

As long as n8n is running and the workflow is published, the production webhook is available.

---

## 18. GET vs POST Behavior

Opening the production webhook directly in a browser produced an error similar to:

```text
This webhook is not registered for GET requests.
Did you mean to make a POST request?
```

This was expected because:

```text
Browser address bar â†’ GET
Webhook configuration â†’ POST
```

The production webhook therefore had to be tested using an actual POST request.

---

## 19. Production ATTACK Test

The production webhook was tested with:

```powershell
$body = @{
    detection_id = 99
    prediction = "ATTACK"
    attack = $true
    confidence = 0.991
    model = "XGBoost"
} | ConvertTo-Json

Invoke-RestMethod `
    -Uri "http://localhost:5678/webhook/sentinel-detection" `
    -Method POST `
    -ContentType "application/json" `
    -Body $body
```

The published workflow returned:

```text
status       : CRITICAL
message      : Sentinel detected malicious network traffic
detection_id : 99
model        : XGBoost
confidence   : 0.991
```

This confirmed the production webhook worked without manual test activation.

---

## 20. Concepts Learned

Phase 4 introduced the foundations of automation engineering.

### Workflow
A connected sequence of automation steps.

### Node
A single trigger, action, transformation, or decision.

### Trigger
The event that starts the workflow.

### Webhook
An HTTP endpoint that lets one system notify another system that something happened.

### JSON Payload
Structured data transferred between systems.

### Expression
A dynamic reference to incoming data.

Example:

```text
{{ $json.body.confidence }}
```

### Conditional Logic
Using an IF node to evaluate conditions.

### Branching
Running different actions based on a condition result.

### Data Transformation
Using Edit Fields to convert raw input into structured output.

### Test Webhook
Temporary development webhook.

### Production Webhook
Persistent webhook used by a published workflow.

### Respond to Webhook
Returns structured output to the system that triggered the workflow.

### Publishing
Makes the workflow available through its production webhook.

---

## 21. Problems Encountered

### Boolean Type Mismatch

The IF node initially treated the attack value as text.

Resolved by using:

```text
{{ $json.body.attack }}
```

directly in Expression mode.

### Test Webhook 404

The test webhook returned 404 when no active listener existed.

Resolved by using:

```text
Listen for test event
```

or:

```text
Execute workflow
```

before sending the test POST.

### No Data in Downstream Node

After restarting n8n, downstream nodes had no fresh input.

Resolved by sending a new webhook event first.

### GET Request to POST Webhook

Opening the production URL in Chrome sent a GET request and failed.

Resolved by sending a POST request using PowerShell.

---

## 22. Phase 4 Final Architecture

```text
              SENTINEL â€” PHASE 4

          External Test Payload
                   â†“
             HTTP POST JSON
                   â†“
            n8n Webhook
                   â†“
               IF attack?
              â†™          â†˜
           TRUE          FALSE
            â†“              â†“
   Prepare Attack     Prepare Benign
       Alert              Result
            â†“              â†“
   CRITICAL Output      SAFE Output
            â†“              â†“
    Respond to          Respond to
      Webhook             Webhook
```

Published production endpoint:

```text
POST http://localhost:5678/webhook/sentinel-detection
```

---

## 23. Phase 4 Outcome

By the end of Phase 4:

- n8n was installed and running locally.
- A Sentinel automation workflow was created.
- A webhook trigger accepted Sentinel-style JSON.
- Dynamic fields were read using n8n expressions.
- The attack Boolean was evaluated correctly.
- ATTACK and BENIGN events were routed separately.
- ATTACK events produced CRITICAL responses.
- BENIGN events produced SAFE responses.
- Both branches returned structured JSON.
- The workflow was published.
- The production webhook was activated.
- The production webhook worked without manual test execution.

Sentinel now had a working automation engine capable of receiving detection events and routing them through conditional logic.

---

## 24. Transition to Phase 5

Phase 4 answered:

> **Can n8n receive Sentinel-style detection data and automatically react to it?**

The answer was yes.

However, the payloads were still being sent manually from PowerShell.

Phase 5 will replace the fake sender with the real Sentinel backend.

Target architecture:

```text
77 Network Features
        â†“
POST /predict
        â†“
FastAPI
        â†“
XGBoost
        â†“
Save Detection to PostgreSQL
        â†“
FastAPI sends detection event
        â†“
n8n Production Webhook
        â†“
IF attack?
    â†™         â†˜
CRITICAL      SAFE
```

Phase 5 therefore connects Sentinel's real ML inference pipeline directly to the automation workflow built in Phase 4.

---

## Phase Status

**Phase 4 â€” n8n Automation Foundation: âœ… COMPLETE**
