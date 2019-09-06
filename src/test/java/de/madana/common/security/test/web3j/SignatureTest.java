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
package de.madana.common.security.test.web3j;

import de.madana.common.security.web3j.Signature;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class SignatureTest
{
	@Test
	public void testIsAddress() {
		Assert.assertFalse(Signature.isAddress("test"));
		Assert.assertTrue(Signature.isAddress("0x1FE31cf2A2e78cce2E933ae2EE36fc712BaF7Ba2"));
	}
	@Test
	public void testValidateSignature() {
		String address = "0x1FE31cf2A2e78cce2E933ae2EE36fc712BaF7Ba2";
		String message = "To login into the communityhub, please sign this nonce: U4OEYRLH71O245GWAWKY35";
		String signature = "0xeeca914101067f9062723e132f0d0d5bc79c62f463e23425ea07628d071178a91679fb27ad46f16af99e2aeabd0159a763ebbcce9453259883c44d60f0521e741c";
		Assert.assertTrue(Signature.validateSignature(address,message,signature));
		Assert.assertFalse(Signature.validateSignature(address,message+"test",signature));

		signature = "0x2c6401216c9031b9a6fb8cbfccab4fcec6c951cdf40e2320108d1856eb532250576865fbcd452bcdc4c57321b619ed7a9cfd38bd973c3e1e0243ac2777fe9d5b1b";
		address = "0x31b26e43651e9371c88af3d36c14cfd938baf4fd";
		message = "v0G9u7huK4mJb2K1";
		Assert.assertTrue(Signature.validateSignature(address,message,signature));
	}
}	
