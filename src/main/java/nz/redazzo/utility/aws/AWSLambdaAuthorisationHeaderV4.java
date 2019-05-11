package nz.redazzo.utility.aws;

import org.apache.commons.codec.binary.Hex;
import org.joda.time.DateTime;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;
import java.io.UnsupportedEncodingException;
import java.net.ProtocolException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;


/**
 * <p>
 *     Signs AWS Lambda requests using signature version 4.
 * </p>
 * <p>
 *     Written in response to numerous framework and library approaches that were
 *     a thousand times too complicated and introduced more pain than they were worth.
 * </p>
 * <p>
 *     @see <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html">Authenticating Requests: Using the Authorization Header (AWS Signature Version 4)</a>
 * </p>
 */

public class AWSLambdaAuthorisationHeaderV4 {


    private String apiKey;
    private String region = "us-east-1";
    private String accessKey;
    private String secretKey;

    public AWSLambdaAuthorisationHeaderV4() {
    }

    /**
     * Sets the region for the Lambda call. Defaults to "us-east-1".
     *
     * @param region The Amazon AWS region
     */
    public void setRegion(String region) {
        this.region = region;
    }

    /**
     * Sets the credentials
     *
     * @param secretKey
     * @param accessKey
     * @param apiKey
     */
    public void setCredentials(String secretKey, String accessKey, String apiKey) {
        this.apiKey = apiKey;
        this.accessKey = accessKey;
        this.secretKey = secretKey;
    }

    /**
     * Set the HTTP header request AWS Lambda authorisation fields.
     *
     * @param connection
     * @return
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws ProtocolException
     */
    public HttpsURLConnection signHTTPHeaderRequest(HttpsURLConnection connection) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {

        DateTime today = DateTime.now();
        String requestDateTime = getISODateFormattedString(today, "YYYYMMdd'T'hhmmss'Z'");

        // Request date time as above.
        String credentialScope = getISODateFormattedString(today, "YYYYMMdd") + "/" + "execute-api/aws4_request";

        String hexSignature = getHexSignature(today);
        String authorization = getAuthorization(credentialScope, hexSignature);

        connection.setRequestProperty("X-Amz-Date", requestDateTime);
        connection.setRequestProperty("Authorization", authorization);
        connection.setRequestProperty("x-api-key", apiKey);
        connection.setRequestProperty("Content-Type", "application/json");

        return connection;

    }

    private String getAuthorization(String credentialScope, String hexSignature) {

        String authorization = "AWS4-HMAC-SHA256 Credential=";
        authorization += accessKey;
        authorization += "/" + credentialScope;
        authorization += ", SignedHeaders=content-type;host;x-amz-date;x-api-key";
        authorization += ", Signature=" + hexSignature;
        return authorization;
    }

    private String getHexSignature(DateTime today) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {

        String kSecret = "AWS4" + secretKey;
        byte[] kDate = getHMAC(kSecret.getBytes("UTF-8"), getISODateFormattedString(today, "YYYYMMdd").getBytes("UTF-8"));
        byte[] kRegion = getHMAC(kDate, region.getBytes("UTF-8"));
        byte[] kService = getHMAC(kRegion, "execute-api".getBytes("UTF-8"));
        byte[] kSigning = getHMAC(kService, "aws4_request".getBytes("UTF-8"));
        return Hex.encodeHexString(kSigning);
    }

    private byte[] getHMAC(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {

        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(secret_key);
        byte[] result = sha256_HMAC.doFinal(data);
        return result;
    }

    private String getISODateFormattedString(DateTime dateTime, String pattern) {

        SimpleDateFormat sdf = new SimpleDateFormat(pattern);

        DateTime today = dateTime.now().toDateTimeISO();
        String isoFormattedDate = sdf.format(today.toDate());
        return isoFormattedDate;
    }


}
