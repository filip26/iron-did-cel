# `did:cel` Witness Agent

Service for coordinating oblivious witnessing of did:cel event logs.

## Deployment

```bash
gcloud functions deploy witness-agent \
    --runtime=java25 \
    --trigger-http \
    --entry-point=WitnessAgent \
    --concurrency=10 \
    --cpu=1 \
    --set-env-vars STORAGE_BUCKET=your-bucket-name \
