package OpenIDModel;

public class AccessTokenModel 
{
      int uid;
      String clientId,accessToken,scope,timeStamp;
      
	@Override
	public String toString() {
		return "AccessTokenModel [uid=" + uid + ", clientId=" + clientId + ", accessToken=" + accessToken + ", scope="
				+ scope + ", timeStamp=" + timeStamp + "]";
	}
	public AccessTokenModel(int uid, String clientId, String accessToken, String scope, String timeStamp) 
	{
		this.uid = uid;
		this.clientId = clientId;
		this.accessToken = accessToken;
		this.scope = scope;
		this.timeStamp = timeStamp;
	}
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
	public String getAccessToken() {
		return accessToken;
	}
	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public String getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}
}
