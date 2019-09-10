/*******************************************************************************
 * Copyright (C) 2018 MADANA
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * @organization:MADANA
 * @author:Frieder Paape
 * @contact:dev@madana.io
 ******************************************************************************/
package de.madana.common.security.web3j;

import java.math.BigInteger;
import java.util.Arrays;

import org.web3j.crypto.*;
import org.web3j.crypto.Sign.SignatureData;
import org.web3j.utils.Numeric;

public class Signature
{

	public static final String PERSONAL_MESSAGE_PREFIX = "\u0019Ethereum Signed Message:\n";

	public static boolean isAddress(String address) {
		String checksum = Keys.toChecksumAddress(address);
		return checksum.equalsIgnoreCase(address);
	}
	
	public static boolean validateSignature(String address, String message, String signature) {
		address = Keys.toChecksumAddress(address);
		String addressRecovered = Signature.ecRecover(message, signature);
		return address.equals(addressRecovered);
	}

	 /** NOTE @source: https://github.com/web3j/web3j/blob/7eab3d5752fb661f58df037a11677f330b8e1117/crypto/src/test/java/org/web3j/crypto/ECRecoverTest.java
         */
	public static String ecRecover(String message, String signature) {

		String prefix = PERSONAL_MESSAGE_PREFIX + message.length();
		byte[] msgHash = Hash.sha3((prefix + message).getBytes());

		byte[] signatureBytes = Numeric.hexStringToByteArray(signature);
		if (signatureBytes.length != 65) {
			return null;
		}

		byte v = signatureBytes[64];
		if (v != 27 && v != 28) {
			return null;
		}
		v -= 27; // Transform yellow paper V from 27/28 to 0/1

		ECDSASignature sig = new ECDSASignature(
			new BigInteger(1, 
				(byte[]) Arrays.copyOfRange(signatureBytes, 0, 32)), 
			new BigInteger(1, 
				(byte[]) Arrays.copyOfRange(signatureBytes, 32, 64))
		);

		BigInteger publicKey = Sign.recoverFromSignature(v, sig, msgHash);

		if (publicKey != null) {
			return Keys.toChecksumAddress("0x" + Keys.getAddress(publicKey));
		}
		return null;
	}

}
