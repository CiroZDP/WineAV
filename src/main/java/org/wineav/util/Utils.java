package org.wineav.util;

import java.math.BigInteger;
import java.util.Base64;

public class Utils {

	private Utils() {
	}

	public static String b64t16(String b64) {
		return new BigInteger(Base64.getDecoder().decode(b64)).toString(16);
	}

	public static String b16t64(String hex) {
		return Base64.getEncoder().encodeToString(new BigInteger(hex, 16).toByteArray());
	}

}
