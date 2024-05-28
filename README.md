# oci-rotate-secret-fn
This project is an example piece of code that was written for demonstrating the auto-rotation functionality of OCI Secrets Management Service.  It should be used as a template for evaluating the OCI Functions when using the Auto-Rotation capabilities and not for Production use.  Use at your own discretion.

The example is extended to demonstrate how to auto-rotate a ClientId and Secret for an OCI IAM Confidential OAuth2 application. In this case, the OCI IAM service is responsible for generating the secret via its own internal randomizer function.  Therefore, instead of OCI Secrets randomly generating the secret, this code will receive the Secret from the OCI IAM service and update the OCI Secret Version.

Refer to this blog that walks through the setup of this example in detail.

https://www.ateam-oracle.com/post/automatically-rotate-oci-secrets-using-a-custom-function

![image](https://github.com/tstahl/oci-rotate-secret-fn/assets/1816476/97b2cbdb-2c60-4a22-9db7-c2da37c5cb4a)

**Secret Rotation Orchestration and Stages**

A.) When the next-scheduled rotation time is reached, this will trigger the CustomRotateFunction function to be executed.

 The CustomRotateFunction function will then iterate through the stages in CustomRotateFunction class - 
  
**Custom Function stages:**

The function executes in a series of stages during the Secret rotation flow:

B.) Verify the existing credentials against the OCI IAM /oauth2/token API to get a valid access_token

C.) Upon successful verification, it will retrieve an OAuth2 access_token to perform a self-service update to regenerate it's own Secret via OCI IAM Credential Regeneration API

     https://docs.oracle.com/en/cloud/paas/identity-cloud/rest-api/api-apps-appclient-secret-regenerator.html

D.) The OCI Function will then receive the new Secret response from OCI IAM and write it back to the SecretId - as a pending secret

B.) The function will then verify the new secret contents are valid

D.) Once the new credentials are validated, the secret is promoted from Pending to Current


