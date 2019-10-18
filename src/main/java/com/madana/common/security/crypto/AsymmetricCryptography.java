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
 * @author:Jean-Fabian Wenisch
 * @contact:dev@madana.io
 ******************************************************************************/
package com.madana.common.security.crypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.net.util.Base64;

/**
 * The Class AsymmetricCryptography.
 */
public class AsymmetricCryptography 
{

	private KeyPairGenerator keyGen;
	private KeyPair pair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private static String algorithm="RSA";
	private Cipher cipher;
	private int keylength = 2048;

	private void init() throws NoSuchAlgorithmException, NoSuchPaddingException
	{
		this.cipher = Cipher.getInstance(algorithm);
		this.keyGen = KeyPairGenerator.getInstance(algorithm);
		this.keyGen.initialize(keylength);
	}
	public AsymmetricCryptography() throws NoSuchAlgorithmException, NoSuchPaddingException 
	{
		init();	
	}

	/**
	 * Instantiates a new generate keys.
	 *
	 * @param keylength the keylength
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchProviderException the no such provider exception
	 */
	public AsymmetricCryptography(int keylength) throws NoSuchAlgorithmException, NoSuchPaddingException 
	{
		this.keylength=keylength;
		init();	
	}

	AsymmetricCryptography (byte[] publicKeyBytes , byte []privateKeyBytes ) throws Exception
	{
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
		publicKey = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		init();	
		validateKeypair();
	}
	public AsymmetricCryptography (PublicKey publicKey , PrivateKey privateKey ) throws Exception
	{
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		init();	
		validateKeypair();
	}

	public void validateKeypair() throws Exception
	{
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;
		if(!( rsaPublicKey.getModulus().equals( rsaPrivateKey.getModulus() )
				&& BigInteger.valueOf( 2 ).modPow( rsaPublicKey.getPublicExponent()
						.multiply( rsaPrivateKey.getPrivateExponent() ).subtract( BigInteger.ONE ),
						rsaPublicKey.getModulus() ).equals( BigInteger.ONE )))
		{
			throw new Exception("Keypair is not matching");
		}
	}



	/**
	 * Creates the keys.
	 */
	public void createKeys() 
	{
		this.pair = this.keyGen.generateKeyPair();
		this.privateKey = pair.getPrivate();
		this.publicKey = pair.getPublic();
	}

	/**
	 * Saves both public key and private  key to file names specified
	 * @param fnpub  file name of public key
	 * @param fnpri  file name of private key
	 * @throws IOException
	 */
	public  void SaveKeyPair(String fnpub,String fnpri) throws IOException 
	{ 

		savePublicKeyToFile(fnpub);
		savePrivateKeyToFile(fnpri);
	}
	public void savePrivateKeyToFile(String filename) throws IOException
	{
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(Base64.encodeBase64(getPrivateKeyAsByteArray()));
		fos.close();
	}
	public static PrivateKey convertStringToPrivateKey(String text) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(text.getBytes()));
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return  kf.generatePrivate(spec);

	}
	public static PrivateKey loadPrivateKeyFromFile(String filename)	throws Exception 
	{


		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(keyBytes));
		KeyFactory kf = KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(spec);
	}

	public void savePublicKeyToFile(String filename) throws IOException
	{
		FileOutputStream fos = new FileOutputStream(filename);
		fos.write(Base64.encodeBase64(getPublicKeyAsByteArray()));

		fos.close();
	}
	public static PublicKey convertStringToPublicKey(String text) throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		X509EncodedKeySpec spec =	new X509EncodedKeySpec(Base64.decodeBase64(text));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);

	}
	public static PublicKey loadPublicKeyFromFile(String filename)	throws Exception 
	{

		byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

		X509EncodedKeySpec spec =	new X509EncodedKeySpec(Base64.decodeBase64(keyBytes));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}






	/**
	 * Gets the private key.
	 *
	 * @return the private key
	 */
	public PrivateKey getPrivateKey() 
	{
		return this.privateKey;
	}
	public byte[] getPrivateKeyAsByteArray()
	{
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey.getEncoded());
		return pkcs8EncodedKeySpec.getEncoded();
	}
	public String getPrivateKeyAsString()
	{
		return Base64.encodeBase64String(getPrivateKeyAsByteArray());
	}

	/**
	 * Gets the public key.
	 *
	 * @return the public key
	 */
	public PublicKey getPublicKey() 
	{
		return this.publicKey;
	}

	public byte[] getPublicKeyAsByteArray()
	{
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKey.getEncoded());		
		return x509EncodedKeySpec.getEncoded();
	}
	public String getPublicKeyAsString()
	{
		return Base64.encodeBase64String(getPublicKeyAsByteArray());
	}
	/**
	 * Gets the keypair.
	 *
	 * @return the keypair
	 */
	public KeyPair getKeypair()
	{
		return pair;
	}
	/**
	 * Encrypt text.
	 *
	 * @param msg the msg
	 * @param key the key
	 * @return the string
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 * @throws UnsupportedEncodingException the unsupported encoding exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	public String encryptText(String msg, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException{
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.encodeBase64String(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	/**
	 * Decrypt text.
	 *
	 * @param msg the msg
	 * @param key the key
	 * @return the string
	 * @throws InvalidKeyException the invalid key exception
	 * @throws UnsupportedEncodingException the unsupported encoding exception
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 */
	public String decryptText(String msg, PublicKey key) throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.decodeBase64(msg)), "UTF-8");
	}
	/**
	 * Encrypt file.
	 *
	 * @param input the input
	 * @param output the output
	 * @param key the key
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws GeneralSecurityException the general security exception
	 */
	public void encryptFile(byte[] input, File output, PrivateKey key) throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.ENCRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	/**
	 * Decrypt file.
	 *
	 * @param input the input
	 * @param output the output
	 * @param key the key
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws GeneralSecurityException the general security exception
	 */
	public void decryptFile(byte[] input, File output, PublicKey key) throws IOException, GeneralSecurityException {
		this.cipher.init(Cipher.DECRYPT_MODE, key);
		writeToFile(output, this.cipher.doFinal(input));
	}

	/**
	 * Write to file.
	 *
	 * @param output the output
	 * @param toWrite the to write
	 * @throws IllegalBlockSizeException the illegal block size exception
	 * @throws BadPaddingException the bad padding exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	private void writeToFile(File output, byte[] toWrite) throws IllegalBlockSizeException, BadPaddingException, IOException
	{
		FileOutputStream fos = new FileOutputStream(output);
		try
		{
			fos.write(toWrite);
			fos.flush();
		}
		finally
		{
			fos.close();
		}
	}
	/**
	 * 
	 * @param plainText
	 * @param signature
	 * @param publicKey
	 * @return
	 * @throws Exception
	 */
	public boolean verify(String plainText, String signature) throws Exception
	{
		Signature publicSignature = Signature.getInstance("SHA256withRSA");
		publicSignature.initVerify(publicKey);
		publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
		byte[] signatureBytes = Base64.decodeBase64(signature);
		return publicSignature.verify(signatureBytes);
	}
	/**
	 * 
	 * @param plainText
	 * @param privateKey
	 * @return
	 * @throws Exception
	 */
	public String sign(String plainText) throws Exception
	{
		Signature privateSignature = Signature.getInstance("SHA256withRSA");
		privateSignature.initSign(privateKey);
		privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
		byte[] signature = privateSignature.sign();
		return Base64.encodeBase64String(signature);
	}


}
