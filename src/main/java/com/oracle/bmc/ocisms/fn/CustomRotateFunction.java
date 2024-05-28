package com.oracle.bmc.ocisms.fn;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode; 

import com.oracle.bmc.ClientConfiguration;
import com.oracle.bmc.auth.ResourcePrincipalAuthenticationDetailsProvider;
import com.oracle.bmc.model.BmcException;
import com.oracle.bmc.retrier.RetryConfiguration;
import com.oracle.bmc.secrets.SecretsClient;
import com.oracle.bmc.secrets.model.Base64SecretBundleContentDetails;
import com.oracle.bmc.secrets.model.SecretBundle;
import com.oracle.bmc.secrets.requests.GetSecretBundleRequest;
import com.oracle.bmc.vault.VaultsClient;
import com.oracle.bmc.vault.model.Base64SecretContentDetails;
import com.oracle.bmc.vault.model.Secret;
import com.oracle.bmc.vault.model.SecretContentDetails;
import com.oracle.bmc.vault.model.UpdateSecretDetails;
import com.oracle.bmc.vault.requests.GetSecretRequest;
import com.oracle.bmc.vault.requests.UpdateSecretRequest;
import com.oracle.bmc.vault.responses.GetSecretResponse;
import com.oracle.bmc.waiter.DelayStrategy;
import com.oracle.bmc.waiter.ExponentialBackoffDelayStrategy;
import com.oracle.bmc.waiter.MaxAttemptsTerminationStrategy;
import com.oracle.bmc.waiter.MaxTimeTerminationStrategy;
import com.oracle.bmc.waiter.TerminationStrategy;
import com.oracle.bmc.waiter.Waiter;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;
import lombok.With;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.oracle.bmc.ocisms.fn.ClientCredAuth;
import com.oracle.bmc.ocisms.fn.RotateAppIdSecret;

/*
 *         SecretContent required to be a JSON string with the following format:
 *             {
 *               "iamDomainInstanceId" : "idcs-xxxxxx,
 *               "appId" : "Unqiue AppID",
 *               "clientId" : "ClientID from IDCS - NOT the OCID,AppId, or  Name",
 *               "appSecret" ': "Secret for the ClientID"
 *              }
 */

public class CustomRotateFunction {

    private static final int NOT_FOUND = Response.Status.NOT_FOUND.getStatusCode();
    private static final int SUCCESS_CODE = Response.Status.OK.getStatusCode();
    private static final int INTERNAL_SERVER_ERROR = Response.Status.INTERNAL_SERVER_ERROR.getStatusCode();
    final ResourcePrincipalAuthenticationDetailsProvider provider = ResourcePrincipalAuthenticationDetailsProvider.builder().build();
    private final SecretsClient secretsDpClient;
    private final VaultsClient secretsCpClient;
    private final ObjectMapper objectMapper;

    @Inject
    public CustomRotateFunction() {
        try {
            String region = System.getenv("OCI_RESOURCE_PRINCIPAL_REGION");
            ClientConfiguration clientConfiguration = ClientConfiguration.builder()
                    .retryConfiguration(RetryConfiguration.builder()
                            .delayStrategy(new ExponentialBackoffDelayStrategy(61_000L))
                            .terminationStrategy(new MaxAttemptsTerminationStrategy(5))
                            .retryCondition((@NonNull BmcException e) -> e.getStatusCode() == 429)
                            .build())
                    .build();
            secretsDpClient = SecretsClient.builder()
                    .region(region)
                    .configuration(clientConfiguration)
                    .build(provider);
            secretsCpClient = VaultsClient.builder()
                    .region(region)
                    .configuration(clientConfiguration)
                    .build(provider);
            objectMapper = new ObjectMapper();
        } catch (Throwable ex) {
            System.err.println("Connection failed. Try again! " + ex.getMessage());
            throw ex;
        }
    }

    private void validateCredentials(AppIdCredentials credentials) throws IllegalAccessException {
        Field[] fields = credentials.getClass().getDeclaredFields();
        for (Field field : fields) {
            if (field.get(credentials) == null) {
                throw new NullPointerException(field.getName() + " key is missing from the secret json");
            }
        }
    }
// THS IS USEFUL FOR THE JSON PIECE
//
    private AppIdCredentials parseSecretBundle(SecretBundle secretBundle) throws JsonProcessingException, IllegalAccessException {
        String base64SecretContent = ((Base64SecretBundleContentDetails) secretBundle.getSecretBundleContent()).getContent();
        String rawSecret = new String(Base64.getDecoder().decode(base64SecretContent.getBytes(StandardCharsets.UTF_8)));
        AppIdCredentials credentials = objectMapper.readValue(rawSecret, AppIdCredentials.class);
        validateCredentials(credentials);
        return credentials;
    }

    private newClientSecret parseSecretReturn(String rawSecret) throws JsonProcessingException, IllegalAccessException {
              newClientSecret newSecret = objectMapper.readValue(rawSecret, newClientSecret.class);
              System.out.println("APPID" + newSecret.getAppId());
              return newSecret;
    }

    private extractAT parseAuthnResp(String authResp) throws JsonProcessingException, IllegalAccessException {
            extractAT accessToken = objectMapper.readValue(authResp, extractAT.class);
            return accessToken;
   }

    private void waitForSecretActivation(String secretId) throws Exception {
        try {
            System.out.println("Waiting for the secret to transition from UPDATING to ACTIVE.");
            TerminationStrategy terminationStrategy = new MaxTimeTerminationStrategy(300000);
            DelayStrategy delayStrategy = new ExponentialBackoffDelayStrategy(30000);
            Waiter<GetSecretRequest, GetSecretResponse> getSecretResponseWaiter =
                    secretsCpClient.getWaiters().forSecret(GetSecretRequest.builder()
                            .secretId(secretId)
                            .build(), Secret.LifecycleState.Active, terminationStrategy, delayStrategy);
            getSecretResponseWaiter.execute();
        } catch (Exception e) {
            System.err.println("Error in secret " + secretId + " state change to ACTIVE: " + e.getMessage());
            throw e;
        }
    }

// changed form private to public
//    private boolean doesConnectionSucceed(SecretBundle secretBundle) {
    private String  doesConnectionSucceed(SecretBundle secretBundle) {
        try {
        	System.out.println("doesConnectionSucceed");

		// Convert Secret Bundle to get current ClientID/Secret
                 AppIdCredentials currentCreds = parseSecretBundle(secretBundle);
                 System.out.println("APPID IN VERIFYCONN: " + currentCreds.getAppId());
		 System.out.println("IDCS DOMAIN ID: " +  currentCreds.getIamDomainInstanceId());

		String iamDomainInstanceId = currentCreds.getIamDomainInstanceId();
		String clientID = currentCreds.getClientId();
		String clientSecret = currentCreds.getAppSecret();
	        String str = clientID + ":" + clientSecret;

		//base64 current payload creation for token
	        Base64.Encoder enc = Base64.getEncoder();
		byte[] strenc = enc.encode(str.getBytes("UTF-8"));
	
		//System.out.println("Base64 Encoded String : " + new String(strenc,"UTF-8"));
		String basicCred = new String(strenc,"UTF-8");
		ClientCredAuth p = new ClientCredAuth();
	
		String authResp = p.getAccessToken("https://" + iamDomainInstanceId + ".identity.oraclecloud.com:443/oauth2/v1/token", "Basic " + basicCred);
		extractAT at = parseAuthnResp(authResp);
		String accessTokenRet = at.getAccess_token();

		// Need to parse in order to get the ACCESS TOKEN to use
		// Need To Return Said Token - or store it in the Object extractAT
	        return accessTokenRet;

        } catch (Exception ex) {
            System.err.println("AppID connection failed. Try again: " + ex.getMessage());
            return "false";
        }
    }

    private void updateTargetSystemCredentials(SecretBundle currentSecretBundle, SecretBundle pendingSecretBundle) throws Exception {
        System.out.println("Updating credentials for the target system.");
        try {
 		// INSERT LOGIC TO UPDATE TARGET
                System.out.println("Target system updated with new credentials.");
            }
         catch (Exception e) {
            throw new Exception("Error in updating credentials for target system. Please try again! ", e);
        }
    }

    private SecretBundle getSecretBundleFromVersion(String secretId, long versionNo) {
        try {
            System.out.println("Fetching version " + versionNo + "  of secret " + secretId);
            SecretBundle secretBundle = secretsDpClient.getSecretBundle(GetSecretBundleRequest.builder()
                    .secretId(secretId)
                    .versionNumber(versionNo)
                    .build()).getSecretBundle();
            System.out.println( "Version " + versionNo + " fetched for secret " + secretId);
            return secretBundle;
        } catch (BmcException bmc) {
            if (bmc.getStatusCode() == NOT_FOUND) {
                System.out.println("Version " + versionNo + "does not exist or user not authorised for secret " + secretId);
                return null;
            } else {
                System.err.println("Something went wrong in fetching secret bundle. Please try again! " + bmc);
                throw bmc;
            }
        } catch (Exception ex) {
            System.err.println("Failed to get the secret bundle: " + ex);
            throw ex; // Re-throw the exception for handling in the calling function.
        }
    }

    private SecretBundle getSecretBundleFromStage(String secretId, GetSecretBundleRequest.Stage stage) {
        try {
            System.out.println("Fetching the " + stage + " version of secret " + secretId);
            SecretBundle secretBundle = secretsDpClient.getSecretBundle(GetSecretBundleRequest.builder()
                    .secretId(secretId)
                    .stage(stage)
                    .build()).getSecretBundle();
            System.out.println(stage + " version fetched for secret " + secretId);
            return secretBundle;
        } catch (BmcException bmc) {
            if (bmc.getStatusCode() == NOT_FOUND) {
                System.out.println(stage + " version does not exist or user not authorised for secret " + secretId);
                return null;
            } else {
                System.err.println("Something went wrong in fetching secret bundle. Please try again! " + bmc);
                throw bmc;
            }
        } catch (Exception ex) {
            System.err.println("Failed to get the secret bundle: " + ex);
            throw ex; // Re-throw the exception for handling in the calling function.
        }
    }

    private SecretBundle getPendingSecretBundle(String secretId) {
        return getSecretBundleFromStage(secretId, GetSecretBundleRequest.Stage.Pending);
    }

    private SecretBundle getCurrentSecretBundle(String secretId) {
        return getSecretBundleFromStage(secretId, GetSecretBundleRequest.Stage.Current);
    }

    private SecretRotationOutput buildResponse(String message, int statusCode, Long version) {
        System.out.println(message);
        return SecretRotationOutput.builder()
                .returnMessage(message)
                .responseCode(statusCode)
                .versionNo(version)
                .build();
    }

    private SecretRotationOutput buildResponse(String message, int statusCode) {
        return buildResponse(message, statusCode, null);
    }

    /**
     * Verifies successful connection to the target system using either the pending
     * or the current version of the secret.
     * Returns the version number of the pending or current version with which the
     * Returns null for versionNo if the connection using either version is unsuccessful.
     */

    private SecretRotationOutput verifyConnection(String secretId) {
        System.out.println("Verifying connection request for target system using secret " + secretId);
        try {
            SecretBundle pendingSecretBundle = getPendingSecretBundle(secretId);
            if (pendingSecretBundle != null && doesConnectionSucceed(pendingSecretBundle) != null) {

		System.out.println("PENDING sgecret Bundle conn succeed");

                return buildResponse("Connection using the pending secret version was successful!", SUCCESS_CODE, pendingSecretBundle.getVersionNumber());
            }

            System.out.println("Connection failed for pending secret version. Trying with current secret version.");

            SecretBundle currentSecretBundle = getCurrentSecretBundle(secretId);
            if (currentSecretBundle != null) {
                if (doesConnectionSucceed(currentSecretBundle) != null) {

		System.out.println("CURRENT Secret Bundle conn succeed");

                    return buildResponse("Connection using the current secret version was successful!", SUCCESS_CODE, currentSecretBundle.getVersionNumber());
                } else {
                    return buildResponse("Connection using the current secret version was unsuccessful.", Response.Status.BAD_REQUEST.getStatusCode());
                }
            } else {
                return buildResponse("Current version of the secret not found.", NOT_FOUND);
            }
        } catch (Exception e) {
            return buildResponse(e.getMessage(), INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Creates a new pending version of the secret.
     * Does not create a newer version if a pending version already exists.
     */
    private SecretRotationOutput createNewPendingVersion(String secretId) {
        try {
            SecretBundle pendingSecretBundle = getPendingSecretBundle(secretId);
            SecretBundle secretBundle = getCurrentSecretBundle(secretId);

            if (pendingSecretBundle != null) {
                return buildResponse("Pending version already exists!", SUCCESS_CODE);
            } else {
                System.out.println("Creating a new pending version..");
                try {

    		String accessToken = doesConnectionSucceed(secretBundle);
		//System.out.println("AccessToken createPendingVersion: " + accessToken);

                 AppIdCredentials currentCreds = parseSecretBundle(secretBundle);
                 System.out.println("APPID IN VERIFYCONN: " + currentCreds.getAppId());
                 System.out.println("IDCS DOMAIN ID: " +  currentCreds.getIamDomainInstanceId());

                String iamDomainInstanceId = currentCreds.getIamDomainInstanceId();
                String appID = currentCreds.getAppId();
                String clientID = currentCreds.getClientId();

                RotateAppIdSecret r = new RotateAppIdSecret();
                String rotateResp = r.rotateSecret("https://" + iamDomainInstanceId + ".identity.oraclecloud.com/admin/v1/AppClientSecretRegenerator", appID , accessToken);

		newClientSecret newSecretResp = parseSecretReturn(rotateResp);

		String updatedSecret = newSecretResp.getClientSecret();
		
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode rootNode = mapper.createObjectNode();
		rootNode.put("iamDomainInstanceId", iamDomainInstanceId);
		rootNode.put("appId", appID);
		rootNode.put("clientId", clientID);
		rootNode.put("appSecret", newSecretResp.getClientSecret());

		String jsonEncStr = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootNode);

		//Base64 encode jSON payload
		  Base64.Encoder enc = Base64.getEncoder();
		  byte[] strenc = enc.encode(jsonEncStr.getBytes("UTF-8"));

		 String newSecretPayload = new String(strenc,"UTF-8");

                secretsCpClient.updateSecret(UpdateSecretRequest.builder()
			    .secretId(secretId)
                            .updateSecretDetails(UpdateSecretDetails.builder()
                                    .secretContent(Base64SecretContentDetails.builder()
                                            .stage(SecretContentDetails.Stage.Pending)
					    .content(newSecretPayload)
                                            .build())
                                    .build())
                            .build());

                    waitForSecretActivation(secretId);

                    return buildResponse("Pending version created successfully!", SUCCESS_CODE);
                } catch (BmcException e) {
                    return buildResponse("Pending version creation failed. " + e.getMessage(), e.getStatusCode());
                }
            }
        } catch (Exception e) {
            return buildResponse(e.getMessage(), INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Updates the target system with the newly created pending version.
     * If the connection already succeeds with the pending version, returns a success response.
     * Returns the versionNumber of the version with which the target system has been updated
     * and should be promoted.
     * Returns null for versionNo if the update is unsuccessful.
     */

    private SecretRotationOutput updateTargetSystem(String secretId, long versionNo) {
 

       try {
            SecretBundle pendingSecretBundle = getPendingSecretBundle(secretId);

		 return buildResponse("Target system updated successfully!", SUCCESS_CODE, pendingSecretBundle.getVersionNumber());

/*            if(pendingSecretBundle == null){
                return buildResponse("No pending version exists.", INTERNAL_SERVER_ERROR);
            }
            if (doesConnectionSucceed(pendingSecretBundle)) {
                return buildResponse("Target system already updated.", SUCCESS_CODE, pendingSecretBundle.getVersionNumber());
            } else {
                SecretBundle currentInputSecretBundle = getSecretBundleFromVersion(secretId, versionNo);
                updateTargetSystemCredentials(currentInputSecretBundle, pendingSecretBundle);
                if (doesConnectionSucceed(pendingSecretBundle)) {
                    return buildResponse("Target system updated successfully!", SUCCESS_CODE, pendingSecretBundle.getVersionNumber());
                } else {
                    return buildResponse("Target system update failed.", INTERNAL_SERVER_ERROR);
                }
            }
*/
        } catch (Exception e) {
            return buildResponse(e.getMessage(), INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Promotes the pending version with the input number to the current version.
     */
    private SecretRotationOutput promotePendingVersion(String secretId, long versionNo) {
        try {

	System.out.println("SecretVersionNo: " + versionNo);
	       secretsCpClient.updateSecret(UpdateSecretRequest.builder()
                    .secretId(secretId)
                    .updateSecretDetails(UpdateSecretDetails.builder()
                            .currentVersionNumber(versionNo)
                            .build())
                    .build());
            waitForSecretActivation(secretId);
		//System.out.println("END OF PROMOTE");

            return buildResponse("Pending version promoted", SUCCESS_CODE);
        } catch (Exception e) {
            return buildResponse(e.getMessage(), INTERNAL_SERVER_ERROR);
        }
    }

    public SecretRotationOutput handleRequest(SecretRotationInput input) {
        return switch (input.getStep()) {
            case VERIFY_CONNECTION -> verifyConnection(input.getSecretId());
            case CREATE_PENDING_VERSION -> createNewPendingVersion(input.getSecretId());
            case UPDATE_TARGET_SYSTEM -> updateTargetSystem(input.getSecretId(), input.getVersionNo());
            case PROMOTE_PENDING_VERSION -> promotePendingVersion(input.getSecretId(), input.getVersionNo());
        };
    }

    public enum RotationSteps {
        VERIFY_CONNECTION("VERIFY_CONNECTION"),
        CREATE_PENDING_VERSION("CREATE_PENDING_VERSION"),
        UPDATE_TARGET_SYSTEM("UPDATE_TARGET_SYSTEM"),
        PROMOTE_PENDING_VERSION("PROMOTE_PENDING_VERSION");

        private static final Map<String, RotationSteps> map;

        static {
            map = new HashMap<>();
            for (RotationSteps v : RotationSteps.values()) {
                map.put(v.getValue(), v);
            }
        }

        private final String value;

        RotationSteps(String value) {
            this.value = value;
        }

        @JsonCreator
        public static RotationSteps create(String key) {
            if (map.containsKey(key)) {
                return map.get(key);
            }
            return null;
        }

        @JsonValue
        public String getValue() {
            return value;
        }
    }

    @Data
    public static class SecretRotationInput {
        private RotationSteps step;
        private String secretId;
        private Long versionNo;
    }

    @Setter
    @Getter
    @AllArgsConstructor
    @Builder(toBuilder = true)
    public static class SecretRotationOutput {
        int responseCode;
        String returnMessage;
        private Long versionNo;
    }

    @Data
    @ToString(callSuper = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder(toBuilder = true)
    @With
    public static class AppIdCredentials {
        String iamDomainInstanceId;
        String appId;
	String clientId;
        String appSecret;
    }

    @Data
    @ToString(callSuper = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder(toBuilder = true)
    @With
    public static class newClientSecret{
        String appId;
        String id;
        String clientSecret;
    }

    @Data
    @ToString(callSuper = true)
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @AllArgsConstructor
    @NoArgsConstructor
    @Builder(toBuilder = true)
    @With
    public static class extractAT{
        String access_token;
        String token_type;
        String expires_in;
    }
}
