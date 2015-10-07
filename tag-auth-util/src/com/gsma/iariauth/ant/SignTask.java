package com.gsma.iariauth.ant;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import com.gsma.iariauth.signer.IARISigner;
import com.gsma.iariauth.util.CertificateUtils;
import com.gsma.iariauth.util.Constants;
import com.gsma.iariauth.util.IARIAuthDocument;
import com.gsma.iariauth.util.IARIAuthDocument.AuthType;

public class SignTask extends Task {

	/******************************
	 *     Settable properties
	 ******************************/

	private String template;
	public void setTemplate(String template) { this.template = template; };

	private String dest;
	public void setDest(String dest) { this.dest = dest; };

	private String iari;
	public void setIari(String iari) { this.iari = iari; };

	private String pkgname;
	public void setPkgname(String pkgname) { this.pkgname = pkgname; };

	private String pkgsigner;
	public void setPkgsigner(String pkgsigner) { this.pkgsigner = pkgsigner; };

	private String keystore;
	public void setKeystore(String keystore) { this.keystore = keystore; };

	private String alias;
	public void setAlias(String alias) { this.alias = alias; };

	private String storepass;
	public void setStorepass(String storepass) { this.storepass = storepass; };

	private String keypass;
	public void setKeypass(String keypass) { this.keypass = keypass; };

	private String pkgkeystore;
	public void setPkgkeystore(String pkgkeystore) { this.pkgkeystore = pkgkeystore; };

	private String pkgalias;
	public void setPkgalias(String pkgalias) { this.pkgalias = pkgalias; };

	private String pkgstorepass;
	public void setPkgstorepass(String pkgstorepass) { this.pkgstorepass = pkgstorepass; };

	private String identifier;
	public void setIdentifier(String identifier) { this.identifier = identifier; };

	private String crl;
	public void setCrl(String crl) { this.crl = crl; };

	private String mode;
	public void setMode(String mode) { this.mode = mode; };

	/******************************
	 *         Execute
	 ******************************/

	public void execute() {
		/* load doc */
		authDoc = new IARIAuthDocument();
		AuthType authType = AuthType.SELF_SIGNED;
		if(template != null) {
			int readErr = authDoc.read(template);
			if(readErr != Constants.OK) {
				throw new BuildException(authDoc.getError());
			}
		} else {
			authDoc.initAsDefault(authType);
		}

		/* set iari */
		String templateIari = authDoc.getIari();
		String cmdIari = iari;
		if(templateIari != null && cmdIari != null) {
			throw new BuildException("IARI is specified both in template and given params");
		}
		if(templateIari == null && cmdIari == null) {
			throw new BuildException("IARI must be specified if not specified in template");
		}
		if(cmdIari != null) {
			authDoc.setIari(cmdIari);
		}
	
		/* set package name */
		String templatePackageName = authDoc.getPackageName();
		String cmdPackageName = pkgname;
		if(templatePackageName != null && cmdPackageName != null) {
			throw new BuildException("Package name is specified both in template and given params");
		}
		if(templatePackageName == null && cmdPackageName != null) {
			authDoc.setPackageName(cmdPackageName);
		}
	
		/* set package signer */
		String templatePackageSigner = authDoc.getPackageSigner();
		String cmdPackageSigner = pkgsigner;
		if(templatePackageSigner != null && cmdPackageSigner != null) {
			throw new BuildException("Package signer is specified both in template and given params");
		}
		if(cmdPackageSigner != null) {
			authDoc.setPackageSigner(cmdPackageSigner);
		} else if(templatePackageSigner == null) {
			/* see if package signer keystore is specified */
			String packageKeystoreName = pkgkeystore;
			if(packageKeystoreName == null) {
				throw new BuildException("Package signer must be specified if not specified in template");
			}
			String packageSignerKeystoreAlias = pkgalias;
			if(packageSignerKeystoreAlias == null) {
				throw new BuildException("No alias given for package signing certificate");
			}
			String packageSignerKeystorePasswd = pkgstorepass;
			if(packageSignerKeystorePasswd == null) {
				throw new BuildException("No password given for package signing keystore");
			}
			KeyStore packageKeystore = CertificateUtils.loadKeyStore(packageKeystoreName, packageSignerKeystorePasswd);
			if(packageKeystore == null) {
				throw new BuildException("Unable to read package keystore");
			}
			try {
				X509Certificate c = (X509Certificate) packageKeystore.getCertificate(packageSignerKeystoreAlias);
				if(c == null) {
					throw new BuildException("Unable to access package signing certificate");
				}
				authDoc.setPackageSigner(CertificateUtils.getFingerprint(c));
			} catch (KeyStoreException e) {
				e.printStackTrace();
				throw new BuildException("Unable to access package signing certificate");
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				throw new BuildException("Unable to read package signing certificate");
			}
		}
	
		/* sign the document */
		IARISigner signer = new IARISigner(authDoc);
		signer.identifier = identifier;
		signer.ksPath = keystore;
		signer.storePass = storepass;
		signer.keyPass = keypass;
		signer.alias = alias;
		signer.crlPath = crl;
	
		int signErr = signer.sign();
		if(signErr != Constants.OK) {
			throw new BuildException(signer.getError());
		}
	
		/* write signed document */
		int writeErr = authDoc.write(dest);
		if(writeErr != Constants.OK) {
			throw new BuildException(authDoc.getError());
		}
	}

	private IARIAuthDocument authDoc;
}
