/*
 * TOTP Generator
 *
 * Authors: Adriano Campos <adrianoribeirocampos@gmail.com>
 *
 * Copyright (C) 2018  Adriano Campos
 *
 * Basead on project freeotp-android
 * https://github.com/freeotp/freeotp-android
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Build: javac TOTP.java
 * RUN: java TOTP
 *
 */
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

public class TOTP
{
	public static String key = "BZGl3ZOcgX/yB+xYLPzWXmb4vjNaM0Q/2AaCJYfhTnd8KdliglbggxHRKwcCK7A1nBVHhXNDrjqEJOZVRDcelJL7YQrAhH2Y6RPEdMeE3x1n/ps5v+1aEg==";
	public static long period = 60;

	public static int digits=6;
	private static String algo = "sha1";
	private static byte[] secret;

	public static void main(String[] args) {
		System.out.println("TOTP Generator");
		System.out.println("Key Base64 Encoded = " + key);
		System.out.println("Period = " + period);
		System.out.println("Digits = " + digits);

		secret = Base64.getDecoder().decode(key);

		System.out.print("Key decoded hex = ");
		for(int i=0; i< secret.length ; i++) {
				String output = String.format("%02x ", secret[i]);
        System.out.print(output);
    }

		long cur = System.currentTimeMillis();

		System.out.println("\ntimestamp = " + cur);

		long counter = cur / 1000 / period;
		//long counter = cur / period;
		System.out.println("counter = " + counter);

    String str = getHOTP(counter + 0);
		System.out.println("HOTP = " + str);
	}

	public static String getHOTP(long counter) {

		// Encode counter in network byte order
		ByteBuffer bb = ByteBuffer.allocate(8);
		bb.putLong(counter);

		// Create digits divisor
		int div = 1;
		for (int i = digits; i > 0; i--)
				div *= 10;

				System.out.println("Algorithm = Hmac" + algo);

		// Create the HMAC
		try {
				Mac mac = Mac.getInstance("Hmac" + algo);
				System.out.println(mac);
				mac.init(new SecretKeySpec(secret, "Hmac" + algo));

				// Do the hashing
				byte[] digest = mac.doFinal(bb.array());

				// Truncate
				int binary;
				int off = digest[digest.length - 1] & 0x0f;
				binary = (digest[off] & 0x7f) << 0x18;
				binary |= (digest[off + 1] & 0xff) << 0x10;
				binary |= (digest[off + 2] & 0xff) << 0x08;
				binary |= (digest[off + 3] & 0xff);

				String hotp = "";

						binary = binary % div;

						// Zero pad
						hotp = Integer.toString(binary);
						while (hotp.length() != digits)
								hotp = "0" + hotp;

				return hotp;
		} catch (InvalidKeyException e) {
				e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
		}

		return "";
	}
}
