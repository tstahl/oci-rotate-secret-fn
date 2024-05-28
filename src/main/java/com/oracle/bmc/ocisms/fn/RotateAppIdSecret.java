package com.oracle.bmc.ocisms.fn;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;

import java.io.IOException;

public class RotateAppIdSecret{

/*
    public static void main(String[] args) {

        try {

	    System.out.println(args[0]);
	    System.out.println(args[1]);

            String result = rotateSecret(args[0], args[1], args[2]);
            System.out.println(result);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
*/
    public static String rotateSecret(String url, String appId, String accessToken) throws IOException {

        String result = "";
        HttpPost post = new HttpPost(url);

	System.out.println("In RotateAppIdSecret.class appId: " + appId);

        StringBuilder json = new StringBuilder();
        json.append("{");
        json.append("\"appId\":\"" + appId + "\",");
        json.append("\"schemas\":[\"urn:ietf:params:scim:schemas:oracle:idcs:AppClientSecretRegenerator\"]");
        json.append("}");

	String bearerToken = "Bearer " + accessToken;

	post.addHeader("Authorization", bearerToken);
	post.addHeader("Content-Type", "application/json");

        post.setEntity(new StringEntity(json.toString()));

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(post)) {

            result = EntityUtils.toString(response.getEntity());
        }
        return result;
    }

}
