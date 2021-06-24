package OpenIDModel;

public class SaveAuthParamModel 
{
		String clientId,redirectUri,scope,responseType,state,nonce;

		@Override
		public String toString() {
			return "SigninCredentialsModel [clientId=" + clientId + ", redirectUri=" + redirectUri + ", scope=" + scope
					+ ", responseType=" + responseType + ", state=" + state + ", nonce=" + nonce + "]";
		}

		public String getClientId() {
			return clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}

		public String getRedirectUri() {
			return redirectUri;
		}

		public void setRedirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
		}

		public String getScope() {
			return scope;
		}

		public void setScope(String scope) {
			this.scope = scope;
		}

		public String getResponseType() {
			return responseType;
		}

		public void setResponseType(String responseType) {
			this.responseType = responseType;
		}

		public String getState() {
			return state;
		}

		public void setState(String state) {
			this.state = state;
		}

		public String getNonce() {
			return nonce;
		}

		public void setNonce(String nonce) {
			this.nonce = nonce;
		}
	}
