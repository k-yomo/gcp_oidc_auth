# gcpauth
Auth library to verify OpenID Connect ID Token from GCP services.

## Common usecase
- When you need to authenticate requests from cloud scheduler on Cloud Run which allows public access

## Usage
<img src="https://github.com/k-yomo/gcpauth/blob/master/example/cloud_scheduler.png" width=50%>

- Assuming you want to verify requests from the above Cloud Scheduler.
```go
issuerEmail := "cloud-scheduler@foo.iam.gserviceaccount.com"
aud := "Ais5cie5"
if err := gcpauth.VerifyIDToken(ctx, issuerEmail, &gcpauth.Config{Aud: aud}); err != nil {
  // return 401
}
// continue
```
