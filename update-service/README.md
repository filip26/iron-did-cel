# Icon `did:cel` Update Service

Updates an existing `did:cel` identifier event log by binding Google Cloud KMS keys to new verification relationships. Replaces the latest DID document state with a provided DID document by updating the event log and orchestrating witnessing.

## Service

#### Request

The request example:

```json
{
  "previousEventHash": "",
  "assertionMethod": {
    "id": "#key-123",
    "resource": "urn:kms:KMS_KEY_ID/cryptoKeyVersions/KMS_KEY_VERSION"  
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
      "resource": "urn:kms:KMS_KEY_ID_2/cryptoKeyVersions/KMS_KEY_VERSION"    
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
  "previousEventHash": "...",
  "operation": {
    "type": "update",
    "data": { }
  },
  "proof": {
  }
}
```

## 🛫 Deploy

### Configuration

The service is configured via the following environment variables:

| Variable | Required | Description |
|----------|----------|------------|
| `KMS_LOCATION` | Yes | Google Cloud region where the KMS key is located (e.g., `us-central1`) |
| `KMS_KEY_RING` | Yes | Name of the Cloud KMS KeyRing |

### IAM Permissions

Create a new service account:

```bash
gcloud iam service-accounts create SA-NAME \
    --display-name="did:cel updater"
```

Grant these roles to the service account:

* `roles/cloudkms.publicKeyViewer` (To detect key algorithms)
* `roles/cloudkms.signer` (To sign)

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
