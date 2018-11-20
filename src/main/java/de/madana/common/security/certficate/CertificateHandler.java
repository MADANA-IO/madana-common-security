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
package de.madana.common.security.certficate;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

// TODO: Auto-generated Javadoc
/**
 * The Class CertificateHandler.
 */
public class CertificateHandler
{
	  static String signatureAlgorithm = "SHA256WithRSA"; 
	/**
	 * Self sign.
	 *
	 * @param keyPair the key pair
	 * @param subjectDN the subject DN
	 * @return the x 509 certificate
	 * @throws OperatorCreationException the operator creation exception
	 * @throws CertificateException the certificate exception
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static X509Certificate selfSign(KeyPair keyPair, String certCN, String certOU, String certO, String certL, String certC) throws OperatorCreationException, CertificateException, IOException
	{
	    Provider bcProvider = new BouncyCastleProvider();
	    Security.addProvider(bcProvider);

	    long now = System.currentTimeMillis();
	    Date startDate = new Date(now);

	    X500Name dnName = new X500Name("CN="+certCN+", OU="+certOU+", O="+certO+", L="+certL+",C="+certC);
	    BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

	    Calendar calendar = Calendar.getInstance();
	    calendar.setTime(startDate);
	    calendar.add(Calendar.YEAR, 20); // <-- 1 Yr validity

	    Date endDate = calendar.getTime();

	  // <-- Use appropriate signature algorithm based on your keyPair algorithm.

	    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

	    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

	    // Extensions --------------------------

	    // Basic Constraints
	    BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

	    certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

	    // -------------------------------------

	    return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
	}
	
	public static PKCS10CertificationRequest createCSR( KeyPair pair, String certificateDN) throws OperatorCreationException
	{
		X500Principal subject = new X500Principal (certificateDN);
		ContentSigner signGen = new JcaContentSignerBuilder(signatureAlgorithm).build(pair.getPrivate());
		PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic());
		PKCS10CertificationRequest csr = builder.build(signGen);
		return csr;
	}
	
	/**
	 * Sign certificate request.
	 *
	 * @param caCert the ca cert
	 * @param caPrivateKey the ca private key
	 * @param csr the csr
	 * @param notBefore the not before
	 * @param notAfter the not after
	 * @return the x 509 certificate
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeyException the invalid key exception
	 * @throws CertificateException the certificate exception
	 * @throws CertIOException the cert IO exception
	 * @throws OperatorCreationException the operator creation exception
	 */
	public static X509Certificate signCertificateRequest(X509Certificate caCert, PrivateKey caPrivateKey, PKCS10CertificationRequest csr, int validateMonths)
					throws NoSuchAlgorithmException, InvalidKeyException, CertificateException, CertIOException, OperatorCreationException {

		  long now = System.currentTimeMillis();
		    Date notBefore = new Date(now);
		    
		    Calendar calendar = Calendar.getInstance();
		    calendar.setTime(notBefore);
		    calendar.add(Calendar.MONTH, validateMonths); 

		    Date notAfter = calendar.getTime();
		JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(csr);
		X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caCert,
				BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, jcaRequest.getSubject(), jcaRequest.getPublicKey());

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
		.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(jcaRequest.getPublicKey()))
		.addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
		.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
		.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));

		// add pkcs extensions
		org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();
		for (org.bouncycastle.asn1.pkcs.Attribute attr : attributes) {
			// process extension request
			if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
				Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
				Enumeration e = extensions.oids();
				while (e.hasMoreElements()) {
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
					Extension ext = extensions.getExtension(oid);
					certificateBuilder.addExtension(oid, ext.isCritical(), ext.getParsedValue());
				}
			}
		}

		ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(caPrivateKey);
		return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateBuilder.build(signer));
	}
	
	

public static X509Certificate convertPEMToCertifcate(String certEntry) throws IOException {
 
        InputStream in = null;
        X509Certificate cert = null;
        try {
            byte[] certEntryBytes = certEntry.getBytes();
            in = new ByteArrayInputStream(certEntryBytes);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
 
            cert = (X509Certificate) certFactory.generateCertificate(in);
        } catch (CertificateException ex) {
 
        } finally {
            if (in != null) {
                    in.close();
            }
        }
        return cert;
    }
	/**
	 * Convert certificate to PEM.
	 *
	 * @param signedCertificate the signed certificate
	 * @return the string
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	public static String convertCertificateToPEM(X509Certificate signedCertificate) throws IOException {
		StringWriter signedCertificatePEMDataStringWriter = new StringWriter();
		JcaPEMWriter pemWriter = new JcaPEMWriter(signedCertificatePEMDataStringWriter);
		pemWriter.writeObject(signedCertificate);
		pemWriter.close();
		return signedCertificatePEMDataStringWriter.toString();
	}

    /**
     * Write to file.
     *
     * @param path the path
     * @param key the key
     * @throws CertificateEncodingException 
     * @throws IOException Signals that an I/O exception has occurred.
     */
	public static void writeToFile(X509Certificate oCert, String path) throws CertificateEncodingException, IOException 
	{
	
		String strPEM = CertificateHandler.convertCertificateToPEM(oCert);
			File f = new File(path);
			f.getParentFile().mkdirs();

			try (PrintStream out = new PrintStream(new FileOutputStream(f))) 
			{
			    out.print(strPEM);
			}
		
	
		
	}
	
	public static X509Certificate getCertificateFromFile(String filename) throws CertificateException, FileNotFoundException
	{
		  CertificateFactory fact = CertificateFactory.getInstance("X.509");
		    FileInputStream is = new FileInputStream (filename);
		    X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
		    return cer;
	}
	
}
