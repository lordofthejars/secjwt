package com.lordofthejars.jwt.generator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.InputStream;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

public class GenerateToken {

    public static final int SECOND = 1000;
    public static final int MINUTE = 60 * SECOND;
    public static final int HOUR = 60 * MINUTE;
    public static final int DAY = 24 * HOUR;
    public static final int YEAR = 365 * DAY;


    public static void main(String args[]) throws IOException, ParseException, JOSEException {

        final InputStream resourceAsStream = GenerateToken.class.getClassLoader().getResourceAsStream("jwks-pair.json");
        final JWKSet localKeys = JWKSet.load(resourceAsStream);

        final JWK jwk = localKeys.getKeys().get(0);
        final RSAKey rsaKey = (RSAKey) jwk;

        final JWSSigner signer = new RSASSASigner(rsaKey);

        final JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject("secure@redhat.istio.com")
            .issuer("secure@redhat.istio.com")
            .issueTime(new Date())
            .claim("role", "user")
            .expirationTime(new Date(new Date().getTime() + 3 * YEAR))
            .build();

        SignedJWT signedJWT = new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
            claimsSet);

        signedJWT.sign(signer);

        String s = signedJWT.serialize();

        System.out.println(s);

        signedJWT = SignedJWT.parse(s);

        final InputStream resourceAsStreamP = GenerateToken.class.getClassLoader().getResourceAsStream("jwks.json");
        final JWKSet localKeysP = JWKSet.load(resourceAsStreamP);

        JWSVerifier verifier = new RSASSAVerifier((RSAKey) localKeysP.getKeys().get(0));
        System.out.println(signedJWT.verify(verifier));

    }

}
