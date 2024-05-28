package com.oracle.bmc.ocisms.fn;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.NameValuePair;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class ClientCredAuth{

/*    public static void main(String[] args) {

        try {
		
	System.out.println(args[0]);
	System.out.println(args[1]);
        String result = getAccessToken(args[0], args[1]);

        } catch (IOException e) {
            e.printStackTrace();
        }

    }
*/
    public static String getAccessToken(String url, String basicCred) throws IOException {

        String result = "";
        HttpPost post = new HttpPost(url);
	
        post.addHeader("Authorization", basicCred);

        List<NameValuePair> urlParameters = new ArrayList<>();
        urlParameters.add(new BasicNameValuePair("grant_type", "client_credentials"));
        urlParameters.add(new BasicNameValuePair("scope", "urn:opc:idm:__myscopes__"));

        post.setEntity(new UrlEncodedFormEntity(urlParameters));

        try (CloseableHttpClient httpClient = HttpClients.createDefault(); 

	    CloseableHttpResponse response = httpClient.execute(post)){
            result = EntityUtils.toString(response.getEntity());
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }
}
