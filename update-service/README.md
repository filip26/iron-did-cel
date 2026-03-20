# Icon `did:cel` Update Service

Updates an existing `did:cel` identifier event log by binding Google Cloud KMS keys to new verification relationships. Replaces the latest DID document state with a provided DID document by updating the event log and orchestrating witnessing.

## Service

#### Request

The request example:

```json
{
  "assertionMethod": {
    "id": "#key-123",
    "resource": "kms:KMS_KEY_ID/cryptoKeyVersions/KMS_KEY_VERSION"  
  },
  "document": {
    "@context": [],
    "id": "did:cel:zW1",
    "heartbeatFrequency": "P..",
    "assertionMethod": [{
      "id": "#...",
      "type": "Multikey",  
      "publicKeyMultibase": "...."
    }],
    "recovery": [{
      "id": "#key-r-1",
      "resource": "kms:KMS_KEY_ID_2/cryptoKeyVersions/KMS_KEY_VERSION"    
    }, {
      "id": "#zDnaexiPSQFLopHAZaY7JWzwZqC1PwQ3NQ1C8c8X4GWDRuMVo",
      "type": "Multikey",
      "controller": "did:cel:zW1...",
      "publicKeyMultibase": "zDnaexiPSQFLopHAZaY7JWzwZqC1PwQ3NQ1C8c8X4GWDRuMVo"
    }],
    "service": [{
      "type": "CelStorageService",
      "serviceEndpoint": [
        "https://storage.googleapis.com/dcel/",
        "..."
      ]
    }]}
}
```

#### Response

```
HTTP/2 200 OK
content-type: application/json

{
  "eventHash": "...",
  "witnessTask": "..."
}
```

## 🛫 Deploy

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
    --display-name="did:cel updater"
```

Grant these roles to the service account:

* `roles/storage.objectUser` (To read and update `did:cel` event log on GCS)
* `roles/cloudkms.publicKeyViewer` (To detect key algorithms)
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