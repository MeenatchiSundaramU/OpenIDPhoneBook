package OpenIDModel;

import java.util.Arrays;

public class DeveloperModel 
{
	private String clientId,clientSecret,appName,redirectUri;
	private byte[] RsaPubKey,RsaPrivateKey;
	
    @Override
	public String toString() {
		return "DeveloperModel [clientId=" + clientId + ", clientSecret=" + clientSecret + ", appName=" + appName
				+ ", redirectUri=" + redirectUri + ", RsaPubKey=" + Arrays.toString(RsaPubKey) + ", RsaPrivateKey="
				+ Arrays.toString(RsaPrivateKey) + ", uid=" + uid + "]";
	}

	public byte[] getRsaPubKey() {
		return RsaPubKey;
	}

	public void setRsaPubKey(byte[] rsaPubKey) {
		RsaPubKey = rsaPubKey;
	}

	public byte[] getRsaPrivateKey() {
		return RsaPrivateKey;
	}

	public void setRsaPrivateKey(byte[] rsaPrivateKey) {
		RsaPrivateKey = rsaPrivateKey;
	}

	private int uid;
	

	public int getUid() {
		return uid;
	}

	public void setUid(int uid) {
		this.uid = uid;
	}

	public String getClientId() {
		return clientId;
	}

	public void setClientId(String clientId) {
		this.clientId = clientId;
	}

	public String getClientSecret() {
		return clientSecret;
	}

	public void setClientSecret(String clientSecret) {
		this.clientSecret = clientSecret;
	}

	public String getAppName() {
		return appName;
	}

	public void setAppName(String appName) {
		this.appName = appName;
	}

	public String getRedirectUri() {
		return redirectUri;
	}

	public void setRedirectUri(String redirectUri) {
		this.redirectUri = redirectUri;
	}
}
