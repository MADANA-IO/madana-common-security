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
package com.madana.common.security.crypto;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.X509Certificate;

import com.madana.common.security.crypto.AsymmetricCryptography;
import com.madana.common.security.certficate.CertificateHandler;

public class AsymmetricCryptographyTest
{
	@Test
	public void testIsAddress() throws Exception {
		AsymmetricCryptography obj = new AsymmetricCryptography();
		obj.createKeys();
		System.out.println(obj.getPublicKeyAsString());
		System.out.println(obj.getPrivateKeyAsString());
		/*
		 * MADANA API, OU = IT, O = MADANA, L = Berlin, C = DE
        	 * Subject: CN = MADANA Nativeclient, O = MADANA
		 */
		String certCN = "MADANA Nativeclient";
		String certOU = "IT";
		String certO = "MADANA";
		String certL = "Berlin";
		String certC = "DE";
		X509Certificate cert = CertificateHandler.selfSign(obj.getKeypair(), certCN, certOU, certO, certL, certC);
		System.out.println(CertificateHandler.convertCertificateToPEM(cert));

		//Assert.assertFalse(Signature.isAddress("test"));
		//Assert.assertTrue(Signature.isAddress("0x1FE31cf2A2e78cce2E933ae2EE36fc712BaF7Ba2"));
	}
}	
