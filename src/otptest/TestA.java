package otptest;

import java.util.HashMap;

/**
 * OTP 김경진
 * @author tony
 *
 */
public class TestA {
	public static void main(String[] args) {
		GoogleOTP otp = new GoogleOTP();
		HashMap<String, String> map = otp.generate("user1", "forbiz.co.kr");
		String otpkey = map.get("encodedKey");
		String url = map.get("url");

		System.out.println("url===>"+url);
		System.out.println("encodedKey=>"+otpkey);

	}
}
