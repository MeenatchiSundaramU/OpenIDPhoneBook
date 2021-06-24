package OpenIDModel;

public class CreateAccModel 
{
	    private String name,email,password,phone,location;

		@Override
		public String toString() {
			return "CreateAccModel [name=" + name + ", email=" + email + ", password=" + password + ", phone=" + phone
					+ ", location=" + location + "]";
		}

		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getEmail() {
			return email;
		}

		public void setEmail(String email) {
			this.email = email;
		}

		public String getPassword() {
			return password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

		public String getPhone() {
			return phone;
		}

		public void setPhone(String phone) {
			this.phone = phone;
		}

		public String getLocation() {
			return location;
		}

		public void setLocation(String location) {
			this.location = location;
		}
	
}
