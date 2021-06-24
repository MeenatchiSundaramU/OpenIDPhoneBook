package OpenIDModel;

public class grantCodeModel 
{
    String clientId,grantCode,timeStamp,scope;
    int uid,refresh_issued;
    @Override
	public String toString() {
		return "grantCodeModel [clientId=" + clientId + ", grantCode=" + grantCode + ", timeStamp=" + timeStamp
				+ ", scope=" + scope + ", uid=" + uid + ", refresh_issued=" + refresh_issued + "]";
	}
	public grantCodeModel(String clientId, String grantCode, String timeStamp, String scope, int uid,int refresh_issued) 
    {
		this.clientId = clientId;
		this.grantCode = grantCode;
		this.timeStamp = timeStamp;
		this.scope = scope;
		this.uid = uid;
		this.refresh_issued = refresh_issued;
	}
	public String getClientId() {
		return clientId;
	}
	public void setClientId(String clientId) {
		this.clientId = clientId;
	}
	public String getGrantCode() {
		return grantCode;
	}
	public void setGrantCode(String grantCode) {
		this.grantCode = grantCode;
	}
	public String getTimeStamp() {
		return timeStamp;
	}
	public void setTimeStamp(String timeStamp) {
		this.timeStamp = timeStamp;
	}
	public String getScope() {
		return scope;
	}
	public void setScope(String scope) {
		this.scope = scope;
	}
	public int getUid() {
		return uid;
	}
	public void setUid(int uid) {
		this.uid = uid;
	}
	public int getRefresh_issued() {
		return refresh_issued;
	}
	public void setRefresh_issued(int refresh_issued) {
		this.refresh_issued = refresh_issued;
	}
	
}
