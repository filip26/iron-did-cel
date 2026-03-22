# Icon `did:cel` Heartbeat Agent

The `did:cel` heartbeat event generator is implemented as a Google Cloud Function that can be scheduled via Google Cloud Scheduler. It uses Google Cloud KMS for secure key management and GCS to read and store the updated event log, providing a solution for managing `did:cel` identifiers liveness and temporal continuity on Google Cloud infrastructure. This setup ensures automated, periodic heartbeat events.

## Service

#### Request

```json
[{
  "id": "did:cel:zW1...",
  "assertionMethod": {
    "id": "#key-123",
    "resource": "kms:KMS_KEY_ID/cryptoKeyVersions/KMS_KEY_VERSION"
  },
  "witnessEndpoint": [
    "https://witness-red-5qnvfghl2q-uc.a.run.app", 
    "https://witness-blue-5qnvfghl2q-ew.a.run.app"
  ]}, {
 
}]
```

#### Response

```
HTTP/2 200 OK
content-type: application/json

[{
  "id": "did:cel:zW1...",
  "eventHash": "...",  
  "witnessTask": "..."
  }, {

}]
```

## Deployment

### Configuration

The service is configured via the following environment variables:

| Variable | Required | Description |
|----------|----------|------------|
| `KMS_LOCATION` | Yes | Google Cloud region where the KMS key is located (e.g., `us-central1`) |
| `KMS_KEY_RING` | Yes | Name of the Cloud KMS KeyRing |
| `BUCKET_NAME` | Yes | GCS bucket for event log persistence. |
| `QUEUE_NAME` | Yes | Cloud Tasks queue for witness agent orchestration. |
| `QUEUE_LOCATION` | Yes | Regional location of the Cloud Tasks queue. |
| `WITNESS_AGENT` | Yes | Witness Agent URL |

### IAM Permissions

Create a new service account:

```bash
gcloud iam service-accounts create SA-NAME \
    --display-name="did:cel heartbeat agent"
```

Grant these roles to the service account:

* `roles/storage.objectUser` (To read and update `did:cel` event log on GCS)
* `roles/cloudkms.publicKeyViewer` (To detect key algorithm)
* `roles/cloudkms.signer` (To sign)
* `roles/cloudtasks.enqueuer` (To schedule witness agent tasks)

```bash
gcloud storage buckets add-iam-policy-binding gs://$BUCKET_NAME \
    --member="serviceAccount:SA-NAME@PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectUser"
```

```bash
gcloud kms keyrings add-iam-policy-binding $KMS_KEY_RING \
  --location=$KMS_LOCATION \
  --member="serviceAccount:SA-NAME@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudkms.publicKeyViewer"
```

```bash
gcloud kms keyrings add-iam-policy-binding $KMS_KEY_RING \
  --location=$KMS_LOCATION \
  --member="serviceAccount:SA-NAME@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudkms.signer"
```

```bash
gcloud tasks queues add-iam-policy-binding $QUEUE_NAME \
  --location=$QUEUE_LOCATION \
  --member="serviceAccount:SA-NAME@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudtasks.enqueuer"
```

### Scheduled Execution

```bash
gcloud services enable cloudscheduler.googleapis.com
```

```bash
gcloud scheduler jobs http JOB_NAME \
    --schedule="0 0 0 * *" \
    --time-zone=UTC \
    --uri=FUNCTION_URL \
    --location= \
    --message-body='["did:cel:...","..."]'
```
