package otptest;

/**
  * OTP 김경진
 * @author tony
 *
 */
public class TestB {
	public static void main(String[] args) {
		GoogleOTP otp = new GoogleOTP();
		String otpkey = "DNV33CPSXGBZFEZO";

		boolean check = otp.checkCode("130247", otpkey);
		System.out.println(check);
	}
}
